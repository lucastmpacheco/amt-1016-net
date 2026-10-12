# amtctl — cliente e protocolo local da central Intelbras AMT 1016 NET

Biblioteca e ferramenta de linha de comando, em Rust, para comunicação com centrais de alarme
Intelbras **AMT 1016 NET** pelo protocolo TCP de rede local (ISECNet, variante "0xE7"), obtido por
engenharia reversa do aplicativo oficial. Permite ler o estado (armada/desarmada, disparo) e emitir
comandos de armar/desarmar sem o aplicativo.

Uso previsto: integração da própria central a software do usuário — automação, painéis, regras de
presença, notificações. Destina-se ao equipamento administrado pelo próprio usuário.

## Modelos
- **Foco:** AMT 1016 NET.
- **Mesma variante local ("0xE7"):** aplicável à linha 2018 NET / E / EG (sujeito a confirmação).
- **Fora de escopo:** AMT 8000 (ISECNet v2, enquadramento distinto).

## Protocolo (resumo)
Transporte: TCP 9009. Enquadramento:
```
[LEN] [0xE7] [TIPO] [DADOS] [CRC16 little-endian] [CHK]
```
- `CHK = 0xFF XOR (todos os bytes anteriores)`
- `CRC16`: CRC-16 reflexivo, inicial 0, sobre `[TIPO][DADOS]`
- Autenticação (`TIPO 0x05`): `DADOS = [0x11] ++ bytes_da_senha ++ [0x34]`, onde `bytes_da_senha`
  interpreta a senha dois caracteres por vez como byte hexadecimal.
- Comandos (`TIPO 0x02`): armar `[0x16, partição]`, desarmar `[0x19, 0x40]`.
- Estado (`TIPO 0x01`): poll `[0x17]`.

Especificação completa: [`docs/PROTOCOLO.md`](docs/PROTOCOLO.md).

## Componentes
- `amt` — biblioteca do protocolo (enquadramento, checksum, CRC, comandos, autenticação).
- `amtctl` — ferramenta de linha de comando sobre a biblioteca.

## Compilação
Requer Rust (`cargo`). Executado em host com acesso de rede à central.
```
cargo build --release
```

## Testes
```
cargo test
```
Os testes validam: o checksum e o CRC contra quadros reais; a montagem de comandos (armar/desarmar)
byte-a-byte; e a montagem do quadro de autenticação (estrutura, CRC e checksum consistentes).

## Metodologia
O aplicativo Android é Xamarin/.NET; a lógica fica em assemblies dentro de `assemblies.blob`
(AssemblyStore "XABA", LZ4), extraídos e analisados com ferramentas de metadados .NET (dnfile/dncil),
sem necessidade de Java.

## Licença
A definir.
