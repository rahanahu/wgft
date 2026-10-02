// Package control はエージェントの制御ソケットを持つ(設計文書 7a.7 節、9 節、10.2c 節)。サーバの側は
// 稼働中のエージェントの中で rotate-key と doctor の指示を受け、エージェントのホストで動く CLI の側は
// rotate-key と agent pubkey を処理する。実行時の状態は Backend の後ろにあり、internal/agent がそれを
// 実装する。internal/agent の下では controlapi と credentials だけを import する。
//
// 本番のコードが package の外から使ってよい名前は Serve、Backend、RotateKey、PublicKey である。
// ServeConn は internal/agent のテストのための口であり、本番のコードは使わない。
// internal/dataplane/deps_test.go の TestAgentModeTestSeamsStayInTests がこれを検査する。
package control
