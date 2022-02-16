//configure this with your own tor port
pub const TOR_ADDR: &str = "127.0.0.1:9150";

use bitcoin::Network;

use crate::offerbook_sync::MakerAddress;

//for now just one of these, but later we'll need multiple for good decentralization
const DIRECTORY_SERVER_ADDR: &str =
    "zfwo4t5yfuf6epu7rhjbmkr6kiysi6v7kibta4i55zlp4y6xirpcr7qd.onion:8080";

#[derive(Debug)]
pub enum DirectoryServerError {
    Reqwest(reqwest::Error),
    Other(&'static str),
}

impl From<reqwest::Error> for DirectoryServerError {
    fn from(e: reqwest::Error) -> DirectoryServerError {
        DirectoryServerError::Reqwest(e)
    }
}

fn network_enum_to_string(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => panic!("dont use directory servers if using regtest"),
    }
}

pub async fn sync_maker_addresses_from_directory_servers(
    network: Network,
) -> Result<Vec<MakerAddress>, DirectoryServerError> {
    // https://github.com/seanmonstar/reqwest/blob/master/examples/tor_socks.rs
    let proxy =
        reqwest::Proxy::all(format!("socks5h://{}", TOR_ADDR)).expect("tor proxy should be there");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("should be able to build reqwest client");
    let res = client
        .get(format!(
            "http://{}/makers-{}.txt",
            DIRECTORY_SERVER_ADDR,
            network_enum_to_string(network)
        ))
        .send()
        .await?;
    if res.status().as_u16() != 200 {
        return Err(DirectoryServerError::Other("status code not success"));
    }
    let mut maker_addresses = Vec::<MakerAddress>::new();
    for makers in res.text().await?.split("\n") {
        let csv_chunks = makers.split(",").collect::<Vec<&str>>();
        if csv_chunks.len() < 2 {
            continue;
        }
        maker_addresses.push(MakerAddress::Tor {
            address: String::from(csv_chunks[1]),
        });
        log::debug!(target:"directory_servers", "expiry timestamp = {} address = {}",
            csv_chunks[0], csv_chunks[1]);
    }
    Ok(maker_addresses)
}

pub async fn post_maker_address_to_directory_servers(
    network: Network,
    address: &str,
) -> Result<u64, DirectoryServerError> {
    let proxy =
        reqwest::Proxy::all(format!("socks5h://{}", TOR_ADDR)).expect("tor proxy should be there");
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("should be able to build reqwest client");
    let params = [
        ("address", address),
        ("net", network_enum_to_string(network)),
    ];
    let res = client
        .post(format!("http://{}/directoryserver", DIRECTORY_SERVER_ADDR))
        .form(&params)
        .send()
        .await?;
    if res.status().as_u16() != 200 {
        return Err(DirectoryServerError::Other("status code not success"));
    }
    let body = res.text().await?;
    let start_bytes = body
        .find("<b>")
        .ok_or(DirectoryServerError::Other("expiry time not parsable1"))?
        + 3;
    let end_bytes = body
        .find("</b>")
        .ok_or(DirectoryServerError::Other("expiry time not parsable2"))?;
    let expiry_time_str = &body[start_bytes..end_bytes];
    let expiry_time = expiry_time_str
        .parse::<u64>()
        .map_err(|_| DirectoryServerError::Other("expiry time not parsable3"))?;
    Ok(expiry_time)
}
