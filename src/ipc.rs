use std::{
    error::Error,
    fs::File,
    io::{self, Read, Write},
    lazy::SyncOnceCell,
    ops::Deref,
    path::{PathBuf, Path},
    sync::{atomic::AtomicUsize, Arc, Mutex, RwLock},
    thread,
    time::Duration,
};

use crossbeam_channel::{unbounded, Receiver, Sender};
use interprocess::local_socket::{LocalSocketListener, LocalSocketStream};

use crate::{driver::coverage_map};
use serde::{Deserialize, Serialize};

fn handle_error(connection: io::Result<LocalSocketStream>) -> Option<LocalSocketStream> {
    connection
        .map_err(|error| eprintln!("Incoming connection failed: {}", error))
        .ok()
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) enum IpcMessage {
    NewCoverage(PathBuf, usize, Vec<usize>),
}

pub(crate) fn create_client(
    socket_path: &Path,
    ipc_channel: crossbeam_channel::Receiver<IpcMessage>,
) -> Result<(), Box<dyn Error>> {
    while !socket_path.exists() {
        std::thread::sleep(Duration::from_millis(250));
    }

    let mut conn = LocalSocketStream::connect(socket_path)?;

    thread::Builder::new()
        .name("IPC-Client".to_owned())
        .spawn(move || {
            loop {
                while let Ok(message) = ipc_channel.try_recv() {
                    conn.write_all(
                        bincode::serialize(&message)
                            .expect("failed to serialize IPC message")
                            .as_slice(),
                    )
                    .expect("failed to write message");
                }

                std::thread::sleep(Duration::from_millis(250));
            }
        })
        .expect("failed to spawn client worker thread");

    Ok(())
}

pub(crate) fn server_socket_paths(server_id: u32) -> (PathBuf, PathBuf) {
    (PathBuf::from(format!("/tmp/fazi-{}.sock", server_id)), PathBuf::from(format!("/tmp/fazi-{}-rebroadcast.sock", server_id)))
}

pub(crate) fn create_server(
    socket_path: &Path,
    rebroadcasting_senders: Arc<Vec<Arc<Sender<IpcMessage>>>>,
    new_input_names: crossbeam_channel::Sender<(PathBuf, usize)>,
) -> Result<(), Box<dyn Error>> {
    let listener = LocalSocketListener::bind(socket_path)?;
    let mut num_clients = 0;
    let mut join_handles = vec![];

    thread::spawn(move || {
        for mut conn in listener.incoming().filter_map(handle_error) {
            num_clients += 1;

            let rebroadcasting_senders = rebroadcasting_senders.clone();
            let new_input_names = new_input_names.clone();

            join_handles.push(
                thread::Builder::new()
                    .name(format!("IPC-Client-Handler-{}", num_clients))
                    .spawn(move || {
                        loop {
                            if let Ok(message) =
                                bincode::deserialize_from::<_, IpcMessage>(&mut conn)
                            {
                                // Rebroadcast this message
                                for sender in &*rebroadcasting_senders {
                                    sender
                                        .send(message.clone())
                                        .expect("failed to rebroadcast emssage to clients");
                                }

                                match message {
                                    IpcMessage::NewCoverage(
                                        input_name,
                                        input_coverage,
                                        new_coverage,
                                    ) => {
                                        let mut coverage = coverage_map()
                                            .lock()
                                            .expect("failed to lock coverage map");
                                        coverage.extend(new_coverage.into_iter());
                                        new_input_names.send((input_name, input_coverage));
                                    }
                                }
                            }
                        }
                    })
                    .expect("failed to spawn IPC thread"),
            );
        }
    });

    Ok(())
}

pub(crate) fn create_rebroadcast_server_worker(
    socket_path: &Path,
    rebroadcasting_receivers: Arc<Vec<Arc<Receiver<IpcMessage>>>>,
    server_receiver: Receiver<IpcMessage>,
) -> Result<(), Box<dyn Error>> {
    let listener = LocalSocketListener::bind(socket_path)?;
    let mut num_clients = 0;
    let mut join_handles = vec![];

    thread::spawn(move || {
        for mut conn in listener.incoming().filter_map(handle_error) {
            let rebroadcasting = (&*rebroadcasting_receivers)[num_clients].clone();
            let server_receiver = server_receiver.clone();

            num_clients += 1;
            join_handles.push(
                thread::Builder::new()
                    .name(format!("IPC-Client-Rebroadcasting-Handler-{}", num_clients))
                    .spawn(move || {
                        loop {
                            while let Ok(input) = server_receiver.try_recv() {
                                conn.write_all(
                                    bincode::serialize(&input)
                                        .expect("failed to serialize new input")
                                        .as_ref(),
                                )
                                .expect("could not send new input to client");
                            }

                            // Check if we have any new inputs waiting for us to push down
                            // to this client
                            while let Ok(input) = rebroadcasting.try_recv() {
                                conn.write_all(
                                    bincode::serialize(&input)
                                        .expect("failed to serialize new input")
                                        .as_ref(),
                                )
                                .expect("could not send new input to client");
                            }

                            std::thread::sleep(Duration::from_millis(250));
                        }
                    })
                    .expect("failed to spawn IPC thread"),
            );
        }
    });

    Ok(())
}

pub(crate) fn create_rebroadcast_client(
    socket_path: &Path,
    new_input_names: crossbeam_channel::Sender<(PathBuf, usize)>,
) -> Result<(), Box<dyn Error>> {
    while !socket_path.exists() {
        std::thread::sleep(Duration::from_millis(250));
    }

    let mut conn = LocalSocketStream::connect(socket_path)?;

    thread::Builder::new()
        .name("IPC-Client".to_owned())
        .spawn(move || {
            if let Ok(message) = bincode::deserialize_from::<_, IpcMessage>(&mut conn) {
                match message {
                    IpcMessage::NewCoverage(input_name, new_input_coverage, new_coverage) => {
                        let mut coverage =
                            coverage_map().lock().expect("failed to lock coverage map");
                        coverage.extend(new_coverage.into_iter());
                        new_input_names.send((input_name, new_input_coverage));
                    }
                }
            }
        })
        .expect("failed to spawn client worker thread");

    Ok(())
}
