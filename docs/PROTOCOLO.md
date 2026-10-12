# Protocolo local Intelbras AMT 1016 NET (ISECNet, variante "0xE7")

Especificação do protocolo TCP de rede local das centrais de alarme Intelbras da família AMT
(foco na **AMT 1016 NET**), obtida por engenharia reversa do aplicativo oficial e do tráfego do
equipamento. Documento de referência para implementação de clientes próprios.

Escopo: comunicação **local por IP** (o mesmo canal do app "AMT Remoto" em modo local). A família
AMT 8000 usa ISECNet v2, com enquadramento distinto, e não é coberta aqui.

## 1. Transporte
A central aceita conexões **TCP na porta 9009**. Uma sessão é uma única conexão TCP na qual o
cliente executa a conexão (§6), a autenticação (§7) e então comandos (§8) e leituras de estado (§9).

## 2. Enquadramento
```
[LEN] [0xE7] [TIPO] [DADOS...] [CRC16 : 2 bytes little-endian] [CHK : 1 byte]
```
| Campo | Definição |
|---|---|
| `LEN`  | Quantidade de bytes após o próprio `LEN` (equivale a `total − 2`). |
| `0xE7` | Marcador de sessão local. |
| `TIPO` | `0x01` para leitura de estado; `0x02` para comandos; `0x05` para autenticação. |
| `CRC16`| CRC-16 (§4) calculado sobre `[TIPO][DADOS]`, gravado em little-endian. |
| `CHK`  | `0xFF XOR (XOR de todos os bytes anteriores)` (§3). |

## 3. Checksum (CHK)
```
CHK = 0xFF XOR (b[0] XOR b[1] XOR ... XOR b[n-1])
```
onde `b[0..n]` são todos os bytes do quadro antes do `CHK` (incluindo `LEN` e `0xE7`).

## 4. CRC16
CRC-16 reflexivo, baseado em tabela, valor inicial `0`, sem XOR final, resultado em little-endian:
```
crc ← 0
para cada byte b de [TIPO][DADOS]:
    crc ← (crc >> 8) XOR TAB[(crc XOR b) AND 0xFF]
```
`TAB` é uma tabela de 256 entradas de 16 bits. Verificação da tabela com vetores conhecidos:
```
CRC(0x02 0x19 0x40) = 0xABD7     CRC(0x02 0x16 0x00) = 0x2874     CRC(0x01 0x17) = 0x7186
```

## 5. Conexão
A conexão inicia com dois quadros fixos, sem segredo:
```
C→S  01 c4 3a                              estabelece a conexão
S→C  07 c4 <6 bytes> <CHK>                 resposta da central (não é usada na autenticação)
C→S  01 c2 3c
S→C  0c c2 "AMT1016 NET" <CHK>             identificação do modelo em ASCII
```

## 6. Autenticação
A autenticação é derivada exclusivamente da senha de acesso remoto; a resposta da conexão (§5)
não participa. O quadro de autenticação tem `TIPO = 0x05` e:
```
DADOS = [0x11] ++ bytes_da_senha ++ [0x34]
```
`0x11` e `0x34` são delimitadores. `bytes_da_senha` resulta de interpretar a string da senha
**dois caracteres por vez como um byte hexadecimal**:
```
bytes_da_senha(S) = [ parse_hex(S[0:2]), parse_hex(S[2:4]), parse_hex(S[4:6]) ]
```
Exemplo (senha de ilustração `112233`): `bytes_da_senha = 11 22 33`, logo
`DADOS = 11 11 22 33 34`, enquadrado por §2 com `TIPO = 0x05`.

Códigos de erro de senha/comando são retornados no byte de estado da resposta (§10).

## 7. Comandos (`TIPO = 0x02`)
`DADOS` é o comando, enquadrado por §2:
```
Armar partição  : [0x16, indice]     indice: 0=A, 1=B, 2=C, 3=D
Desarmar        : [0x19, 0x40]
Bypass de zona  : [0x1B, ...]
```

## 8. Leitura de estado (`TIPO = 0x01`)
```
Poll de estado  : DADOS = [0x17]  → resposta de ~32 bytes
```
Bits de interesse na resposta de estado:
- **armada**: bit `0x08` em um byte de estado;
- **disparo em memória**: bit `0x40` em outro byte (indica que houve disparo).

Há também leitura de estado completo (formato ~46 bytes) com modelo, firmware, bateria, partições
e zonas.

## 9. Códigos de erro
```
0xE0  pacote inválido        0xE1  senha incorreta       0xE2  comando inválido
0xE3  central sem partições  0xE4  zonas abertas         0xE6  bypass negado
0xE7  desarme negado
```

## 10. Metodologia de engenharia reversa
O aplicativo Android é Xamarin/.NET; a lógica reside em assemblies .NET dentro de
`assemblies/assemblies.blob` (AssemblyStore "XABA", entradas comprimidas em LZ4). A extração não
requer Java: desempacota-se o blob e lê-se o IL com ferramentas de metadados .NET (p.ex. dnfile/dncil).
Classes e métodos relevantes: `Packet`, `Crc`, `CommandTypes`, `CreatePartitionArmPacket`,
`CreateDisableAlarmPacket`, `SendIdentify`, `GetPartsInBytes`, `EncryptConnectionCommand`.
O tráfego é observado com um proxy TCP intermediário na rede local.
