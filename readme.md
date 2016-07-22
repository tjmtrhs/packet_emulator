# Packet Emulator

## TL; DR
- ICMP/TCPの通信をエミュレーションする仮想ホストをpythonで軽量に実現
- FWのテストなどにどうぞ

## Usage
- command:  
`# ./emulator testdata.csv`
- require root privilege
- console log
```
$ sudo python emulator.py sample.csv
*** [testServer] settings ***
172.16.0.2
00:00:00:11:11:11
ens35
*** end ***
[DEBUG][testServer]change state to listen
*** [testClient] settings ***
172.16.1.2
00:00:00:22:22:22
ens35
*** end ***
[DEBUG][testClient]ARP resolv 172.16.1.1
[DEBUG][testClient]recv packet
[DEBUG][testClient]recv arp is_at 172.16.1.1 00:15:2b:11:ee:42
[DEBUG][testClient]ARP resolv 172.16.1.1 is 00:15:2b:11:ee:42
[DEBUG][testClient]send ICMP-request
[DEBUG][testServer]recv packet
[DEBUG][testServer]recv icmp-request, send reply
[DEBUG][testClient]recv packet
[DEBUG][testClient]recv icmp-reply
get icmp-reply
```


## Features
- 任意のMACアドレス/IPアドレスを持った仮想ホストを作成可能
  - 1つのプロセス中に複数の仮想ホストを作成可能
  - クライアント2台とか、サーバ3台とか片側だけも可能
- 仮想ホストの機能
  - ARP解決、応答
  - ICMP echo要求、応答
  - TCP/UDPサーバ待ちうけ
  - TCP/UDPクライアント接続、メッセージ送信
- 仮想ホストの接続形態を2種類サポート
  - 直接接続: NICにブリッジされているように振舞う
  - L3接続: NICとの間にL3機器が介在するように振舞う

## Configuration Data (input file)
- ホスト設定
  - 通信を始めるホスト(client) or 通信を待ち受けるホスト (server)
  - 接続形態: 直接接続(direct) or 仮想ルータを介しての接続 (router)
  - 仮想ホストのIPアドレス
  - 仮想ルータのIPアドレス [接続形態==routerの時のみ必須]
  - MACアドレス # directの時は仮想ホストの、routerの時は仮想ルータ
  - パケットを送受信するNIC名
  - FWのIPまたはMACアドレス
- 通信内容
  - プロトコル(icmp, tcp, udp)
  - 待ち受けポート [tcp, udpの時のみ必須]
  - 送信元ポート [tcp, udpの時のみ必須]
- テスト設定
  - タイムアウト時間

## Components (class)
各コンポーネントはそれぞれ別のスレッドで動作する

```
---- emulator.py -----------------------------------------
|                                                        |
|  -- VirtualHost --             -- VirtualServer --     |
|  |               |             |                 |     |
|  |      recv <---+--------+----+----- recv <-----+--+  |
|  |               |        |    |                 |  |  |
|  -----------------        |    -------------------  |  |
|                           |                         |  |
|  -- VirtualClient ----    |    ---- queue -----     |  |
|  |                   |    |    |              |     |  |
|  |       recv <------+----+----+---dispatch---+-----+  |
|  |                   |    |    |              |        |
|  | icmpTest,tcpTest--+--+ |    |   enqueue    |        |
|  |                   |  | |    |     A        |        |
|  ---------------------  | |    ------+---------        |
|                         | |          |                 |
|  -- __main__ --      ---+-+-- nic ---+----             |
|  |            |      |  V V          |   |             |
|  |   readcsv  |      |  sendp    sniff   |             |
|  |      |     |      |      |    |       |             |
|  -------+------      -------+----+--------             |
----------+-------------------+----+----------------------
          |                   V    | 
---- config.csv ----  ---- NIC (Kernel) ----
|    (settings)    |  |                    |
--------------------  ----------------------
```

## Implement

Now writting...
