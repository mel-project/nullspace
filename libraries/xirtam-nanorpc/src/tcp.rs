use std::collections::HashMap;
use std::time::Duration;

use futures_concurrency::future::Race;
use nanorpc::{JrpcId, JrpcRequest, JrpcResponse, RpcService};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use url::Url;

use crate::REQUEST_TIMEOUT_SECS;

pub async fn serve_tcp<S>(addr: impl ToSocketAddrs, service: S) -> anyhow::Result<()>
where
    S: RpcService,
{
    let service = std::sync::Arc::new(service);
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move { handle_connection(service, stream).await });
    }
}

#[derive(Clone)]
pub(crate) struct RawTcpClient {
    cmd_tx: mpsc::Sender<ClientCommand>,
}

impl RawTcpClient {
    pub(crate) fn new(endpoint: Url) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        tokio::spawn(async move { run_tcp_client(endpoint, cmd_rx).await });
        Self { cmd_tx }
    }

    pub(crate) async fn call_raw(
        &self,
        req: JrpcRequest,
    ) -> Result<JrpcResponse, anyhow::Error> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let req_id = req.id.clone();
        self.cmd_tx
            .send(ClientCommand::Call { req, resp_tx })
            .await
            .map_err(|_| anyhow::anyhow!("tcp client task stopped"))?;
        match time::timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), resp_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow::anyhow!("tcp client task stopped")),
            Err(_) => {
                let _ = self.cmd_tx.send(ClientCommand::Cancel { id: req_id }).await;
                Err(anyhow::anyhow!("tcp request timeout"))
            }
        }
    }
}

enum ClientCommand {
    Call {
        req: JrpcRequest,
        resp_tx: oneshot::Sender<Result<JrpcResponse, anyhow::Error>>,
    },
    Cancel {
        id: JrpcId,
    },
}

enum ConnEvent {
    Response(JrpcResponse),
    Closed(anyhow::Error),
}

enum ClientEvent {
    Command(Option<ClientCommand>),
    Connection(Option<ConnEvent>),
}

struct Connection {
    write_tx: mpsc::Sender<String>,
    event_rx: mpsc::Receiver<ConnEvent>,
}

impl Connection {
    async fn connect(endpoint: &Url) -> Result<Self, anyhow::Error> {
        let host = endpoint
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("tcp endpoint missing host"))?;
        let port = endpoint
            .port()
            .ok_or_else(|| anyhow::anyhow!("tcp endpoint missing port"))?;
        let stream = TcpStream::connect(format!("{host}:{port}")).await?;
        let (reader, mut writer) = stream.into_split();

        let (write_tx, mut write_rx) = mpsc::channel::<String>(256);
        let (event_tx, event_rx) = mpsc::channel::<ConnEvent>(256);

        let mut reader = BufReader::new(reader);
        let read_event_tx = event_tx.clone();
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        let _ = read_event_tx
                            .send(ConnEvent::Closed(anyhow::anyhow!(
                                "tcp connection closed"
                            )))
                            .await;
                        break;
                    }
                    Ok(_) => {
                        let trimmed =
                            line.trim_end_matches(|c| c == '\n' || c == '\r').to_string();
                        if trimmed.is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<JrpcResponse>(&trimmed) {
                            Ok(resp) => {
                                if read_event_tx.send(ConnEvent::Response(resp)).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                let _ = read_event_tx
                                    .send(ConnEvent::Closed(anyhow::anyhow!(err)))
                                    .await;
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        let _ = read_event_tx
                            .send(ConnEvent::Closed(anyhow::anyhow!(err)))
                            .await;
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(line) = write_rx.recv().await {
                if writer.write_all(line.as_bytes()).await.is_err()
                    || writer.write_all(b"\n").await.is_err()
                {
                    let _ = event_tx
                        .send(ConnEvent::Closed(anyhow::anyhow!(
                            "tcp connection closed"
                        )))
                        .await;
                    return;
                }
            }
            let _ = event_tx
                .send(ConnEvent::Closed(anyhow::anyhow!(
                    "tcp connection closed"
                )))
                .await;
        });

        Ok(Self { write_tx, event_rx })
    }
}

async fn run_tcp_client(endpoint: Url, mut cmd_rx: mpsc::Receiver<ClientCommand>) {
    let mut connection: Option<Connection> = None;
    let mut in_flight: HashMap<JrpcId, oneshot::Sender<Result<JrpcResponse, anyhow::Error>>> =
        HashMap::new();

    loop {
        let event = if let Some(conn) = connection.as_mut() {
            let cmd_fut = async { ClientEvent::Command(cmd_rx.recv().await) };
            let conn_fut = async { ClientEvent::Connection(conn.event_rx.recv().await) };
            (cmd_fut, conn_fut).race().await
        } else {
            ClientEvent::Command(cmd_rx.recv().await)
        };

        match event {
            ClientEvent::Command(Some(ClientCommand::Call { req, resp_tx })) => {
                if connection.is_none() {
                    match Connection::connect(&endpoint).await {
                        Ok(conn) => connection = Some(conn),
                        Err(err) => {
                            let _ = resp_tx.send(Err(err));
                            continue;
                        }
                    }
                }

                let line = match serde_json::to_string(&req) {
                    Ok(line) => line,
                    Err(err) => {
                        let _ = resp_tx.send(Err(anyhow::anyhow!(err)));
                        continue;
                    }
                };

                let Some(conn) = connection.as_mut() else {
                    let _ = resp_tx.send(Err(anyhow::anyhow!("tcp connection closed")));
                    continue;
                };

                if conn.write_tx.send(line).await.is_err() {
                    let err = anyhow::anyhow!("tcp connection closed");
                    let _ = resp_tx.send(Err(anyhow::anyhow!(err.to_string())));
                    fail_in_flight(&mut in_flight, err.to_string());
                    connection = None;
                    continue;
                }

                in_flight.insert(req.id.clone(), resp_tx);
            }
            ClientEvent::Command(Some(ClientCommand::Cancel { id })) => {
                in_flight.remove(&id);
            }
            ClientEvent::Command(None) => {
                fail_in_flight(&mut in_flight, "tcp client stopped".to_string());
                return;
            }
            ClientEvent::Connection(Some(ConnEvent::Response(resp))) => {
                if let Some(tx) = in_flight.remove(&resp.id) {
                    let _ = tx.send(Ok(resp));
                }
            }
            ClientEvent::Connection(Some(ConnEvent::Closed(err))) => {
                fail_in_flight(&mut in_flight, err.to_string());
                connection = None;
            }
            ClientEvent::Connection(None) => {
                fail_in_flight(&mut in_flight, "tcp connection closed".to_string());
                connection = None;
            }
        }
    }
}

fn fail_in_flight(
    in_flight: &mut HashMap<JrpcId, oneshot::Sender<Result<JrpcResponse, anyhow::Error>>>,
    message: String,
) {
    for (_, tx) in in_flight.drain() {
        let _ = tx.send(Err(anyhow::anyhow!(message.clone())));
    }
}

async fn handle_connection<S>(service: std::sync::Arc<S>, stream: TcpStream)
where
    S: RpcService,
{
    let (reader, mut writer) = stream.into_split();
    let (write_tx, mut write_rx) = mpsc::channel::<String>(256);
    tokio::spawn(async move {
        while let Some(line) = write_rx.recv().await {
            let write_line = async {
                writer.write_all(line.as_bytes()).await?;
                writer.write_all(b"\n").await
            };
            match time::timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), write_line).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return,
            }
        }
    });

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let read_result =
            time::timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), reader.read_line(&mut line))
                .await;
        let Ok(read_result) = read_result else {
            return;
        };
        match read_result {
            Ok(0) => return,
            Ok(_) => {
                let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<JrpcRequest>(trimmed) {
                    Ok(req) => {
                        let write_tx = write_tx.clone();
                        let service = service.clone();
                        tokio::spawn(async move {
                            let resp = service.respond_raw(req).await;
                            if let Ok(payload) = serde_json::to_string(&resp) {
                                let _ = write_tx.send(payload).await;
                            }
                        });
                    }
                    Err(err) => {
                        let resp = json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32700,
                                "message": "Parse error",
                                "data": err.to_string()
                            },
                            "id": json!(null),
                        });
                        let _ = write_tx.send(resp.to_string()).await;
                    }
                }
            }
            Err(_) => return,
        }
    }
}
