//! amtctl — suite de linha de comando da central Intelbras AMT 1016 NET (ISECNet V1).
//!
//! Uso:
//!   amtctl [--host IP] [--port N] --senha DIGITOS <comando> [opcoes]
//!   (senha tambem via env AMT_SENHA; host via AMT_HOST; porta padrao 9009)
//!
//! Comandos:
//!   status                      le o status (armado/desarmado, modelo, bateria)
//!   status-completo             status completo (GET_COMPLETE_STATUS)
//!   armar    [--particao A|B|C|D] [--stay]
//!   desarmar [--particao A|B|C|D]
//!   sirene-off
//!   pgm <n> on|off
//!   panico [--tipo N] --yes     (efeito fisico! exige --yes)
//!   raw <hex...>                envia bytes crus (debug), mostra a resposta
//!
//! A senha NUNCA e impressa nem logada.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use amt::*;

fn main() {
    std::process::exit(match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("erro: {e}");
            2
        }
    });
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        return Ok(());
    }

    let mut host = env_or("AMT_HOST", "");
    let mut port: u16 = 9009;
    let mut senha = std::env::var("AMT_SENHA").unwrap_or_default();
    let mut particao: Option<u8> = None;
    let mut stay = false;
    let mut yes = false;
    let mut enc = Enc::Ascii;
    let mut replay_log: Option<String> = None;
    let mut tipo_panico: u8 = 1;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => { host = take(&args, &mut i)?; }
            "--port" => { port = take(&args, &mut i)?.parse().map_err(|_| "porta invalida")?; }
            "--senha" => { senha = take(&args, &mut i)?; }
            "--particao" => { particao = Some(parse_particao(&take(&args, &mut i)?)?); }
            "--stay" | "--parcial" => { stay = true; }
            "--yes" | "--sim" => { yes = true; }
            "--tipo" => { tipo_panico = take(&args, &mut i)?.parse().map_err(|_| "tipo invalido")?; }
            "--replay-log" => { replay_log = Some(take(&args, &mut i)?); }
            "--enc" => { enc = match take(&args, &mut i)?.as_str() {
                "ascii" => Enc::Ascii, "digitos" | "digits" => Enc::Digitos, "bcd" => Enc::Bcd,
                o => return Err(format!("--enc invalido: {o} (use ascii|digitos|bcd)")),
            }; }
            other => { positionals.push(other.to_string()); }
        }
        i += 1;
    }

    let comando = positionals.first().ok_or("informe um comando (veja --help)")?.clone();

    // 'raw' nao exige senha
    if comando == "raw" {
        let bytes: Vec<u8> = positionals[1..]
            .iter()
            .map(|h| u8::from_str_radix(h.trim_start_matches("0x"), 16))
            .collect::<Result<_, _>>()
            .map_err(|_| "hex invalido em raw")?;
        let resp = transacao(&host, port, &bytes)?;
        println!("resposta ({} bytes): {}", resp.len(), hexs(&resp));
        return Ok(());
    }

    // modo e7 (replay da sessao capturada) para status — a credencial vem dos
    // frames da captura (lidos em tempo de execucao), nao em texto.
    if comando == "status" && replay_log.is_some() {
        let st = status_e7(&host, port, replay_log.as_ref().unwrap())?;
        println!("central (e7): {}", if st.armado { "ARMADO" } else { "DESARMADO" });
        println!("disparo mem.: {}", if st.disparo_memoria { "SIM (houve disparo)" } else { "nao" });
        println!("analogicos  : {:02x} {:02x}", st.ana1, st.ana2);
        println!("status cru  : {}", hexs(&st.raw));
        return Ok(());
    }

    // GERAR frames e7 sintetizados (computacao pura; nao envia nada).
    // Para enviar de verdade: estabelecer a sessao (connect/auth replicados da captura)
    // e transmitir estes bytes na mesma conexao (ex.: via `amtctl raw` dentro da sessao).
    if comando == "gerar" {
        let alvo = positionals.get(1).map(|s| s.as_str()).unwrap_or("");
        let frame = match alvo {
            "armar" => e7_armar(particao),
            "desarmar" => e7_desarmar(),
            "status" => e7_status_poll(),
            _ => return Err("gerar <armar|desarmar|status> [--particao A|B|C|D]".into()),
        };
        println!("{alvo}: {}", hexs(&frame));
        return Ok(());
    }

    if senha.is_empty() {
        return Err("senha nao informada (--senha ou env AMT_SENHA)".into());
    }
    if !senha.bytes().all(|b| b.is_ascii_digit()) {
        return Err("senha deve conter apenas digitos".into());
    }

    let payload: Vec<u8> = match comando.as_str() {
        "status" => cmd_status(),
        "status-completo" => cmd_status_completo(),
        "armar" => cmd_arm(particao, stay),
        "desarmar" => cmd_disarm(particao),
        "sirene-off" => cmd_siren_off(),
        "pgm" => {
            let n: u8 = positionals.get(1).ok_or("pgm: informe o indice")?
                .parse().map_err(|_| "pgm: indice invalido")?;
            let on = matches!(positionals.get(2).map(|s| s.as_str()), Some("on") | Some("1") | Some("ligar"));
            cmd_pgm(n, on)
        }
        "panico" => {
            if !yes {
                return Err("panico tem efeito fisico (sirene/monitoramento). confirme com --yes".into());
            }
            cmd_panic(tipo_panico)
        }
        other => return Err(format!("comando desconhecido: {other} (veja --help)")),
    };

    let frame = build_v1(&payload, &encode_senha(&senha, enc));
    let resp = transacao(&host, port, &frame)?;
    let data = parse_response(&resp)
        .map_err(|e| format!("{e}\n  cru: {}", hexs(&resp)))?;

    if comando == "status" || comando == "status-completo" {
        match parse_status(&data) {
            Ok(s) => {
                println!("central   : modelo=0x{:02x} firmware={}", s.model_code, s.firmware);
                println!("estado    : {}", if s.armado { "ARMADO" } else { "desarmado" });
                println!("particoes : bits=0b{:08b} (multi={})", s.particao_bits, s.multi_particao);
                println!("bateria   : 0x{:02x}", s.bateria);
                println!("dados crus: {}", hexs(&s.raw));
            }
            Err(e) => {
                println!("status nao parseado ({e})");
                println!("dados crus ({} bytes): {}", data.len(), hexs(&data));
            }
        }
    } else {
        // comandos de acao: mostra eco/ack
        println!("ok. resposta ({} bytes): {}", data.len(), hexs(&data));
    }
    Ok(())
}

/// Abre TCP, envia o frame, le a resposta (uma leitura com timeout).
fn transacao(host: &str, port: u16, frame: &[u8]) -> Result<Vec<u8>, String> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("conectar {addr}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(frame).map_err(|e| format!("enviar: {e}"))?;
    stream.flush().ok();
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).map_err(|e| format!("ler: {e}"))?;
    Ok(buf[..n].to_vec())
}

/// Status via protocolo e7: replica os frames C>S da captura (connect/auth/status)
/// numa conexao so e devolve o status de 32B decodificado. Nao expoe senha.
fn status_e7(host: &str, port: u16, log_path: &str) -> Result<amt::StatusE7, String> {
    let texto = std::fs::read_to_string(log_path).map_err(|e| format!("ler log {log_path}: {e}"))?;
    let frames = amt::frames_cs_do_log(&texto);
    if frames.len() < 4 {
        return Err(format!("log tem poucos frames C>S: {}", frames.len()));
    }
    let addr = format!("{host}:{port}");
    let mut s = TcpStream::connect(&addr).map_err(|e| format!("conectar {addr}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok();
    let mut status: Option<Vec<u8>> = None;
    for fr in frames.iter().take(6) {
        s.write_all(fr).map_err(|e| format!("enviar: {e}"))?;
        std::thread::sleep(Duration::from_millis(250));
        let mut buf = [0u8; 512];
        if let Ok(n) = s.read(&mut buf) {
            if let Ok(_) = parse_status_e7(&buf[..n]) {
                status = Some(buf[..n].to_vec());
            }
        }
    }
    let raw = status.ok_or("nao recebi frame de status e7 no replay")?;
    parse_status_e7(&raw)
}

fn take(args: &[String], i: &mut usize) -> Result<String, String> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| format!("faltou valor para {}", args[*i - 1]))
}

fn parse_particao(s: &str) -> Result<u8, String> {
    match s.to_ascii_uppercase().as_str() {
        "A" | "0" => Ok(0),
        "B" | "1" => Ok(1),
        "C" | "2" => Ok(2),
        "D" | "3" => Ok(3),
        _ => Err(format!("particao invalida: {s} (use A|B|C|D)")),
    }
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn print_help() {
    print!("{}", include_str!("help.txt"));
}
