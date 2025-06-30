use bs58;
use poem::{
    IntoResponse, Response, Route, Server, get, handler, http::StatusCode, listener::TcpListener,
    post, web::Json,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use spl_token::instruction::initialize_mint;
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
struct KeyPairData {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
struct GenerateKeyPairOutput {
    pub success: bool,
    pub data: KeyPairData,
}

#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Debug, Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: TokenInstructionData,
}

#[derive(Debug, Serialize)]
struct TokenInstructionData {
    program_id: String,
    accounts: Vec<AccountMetaSerializable>,
    instruction_data: String,
}

#[derive(Debug, Serialize)]
struct AccountMetaSerializable {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[handler]
async fn create_token(Json(payload): Json<CreateTokenRequest>) -> Response {
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: "Invalid mint public key".to_string(),
                }),
            )
                .into_response();
        }
    };

    let mint_authority = match Pubkey::from_str(&payload.mintAuthority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: "Invalid mint authority public key".to_string(),
                }),
            )
                .into_response();
        }
    };

    
    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority,
        None, 
        payload.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: format!("Failed to create instruction: {}", e),
                }),
            )
                .into_response();
        }
    };

    let instruction_data = base64::encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaSerializable {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let response = CreateTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
fn generate_keypair() -> Json<GenerateKeyPairOutput> {
    let keypair = Keypair::new();
    let response = GenerateKeyPairOutput {
        success: true,
        data: KeyPairData {
            pubkey: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            secret: bs58::encode(keypair.secret_bytes()).into_string(),
        },
    };
    Json(response)
}
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/keypair", get(generate_keypair))
        .at("/token/create", post(create_token));

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
