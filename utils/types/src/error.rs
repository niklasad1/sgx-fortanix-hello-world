use derive_more::From;

#[derive(Debug, From)]
pub enum Error {
    IoError(std::io::Error),
    Custom(String),
    NetworkEncoding(bincode::Error),
    // AesmClient(aesm_client::Error),
}
