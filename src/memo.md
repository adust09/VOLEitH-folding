
# 研究の方向性
quicksilverは固定する。vole ithの実装はFASTにあるのでそれを使う
VOLE ZKがboolean circuitであること、AND演算にコストがかかることを考慮し、ハッシュ関数の実行についてベンチマークを計測する。
- verification cost自体が知りたいのではなく、onchain verification costが知りたい
-  solidity verifierよりもonchain verification costを抑えることができるでblobを使ったアプローチを提案する
-  シンプルにsolidity verifierを使った場合とblobを使った場合の比較を行う
-  blobで実現する手法から調査し、milestone2ではどのような実装が必要か(derivarableか)を明記する 
- 上記のonchain verificationとは別に、シンプルなverifiaction costも計測する
- また、client side provingが実用的であることをベンチマークを元に確認する
- milestone3ではchallengingな部分やfuture work, client provingの可能性についてdiscussする

そもそも
KZGでラップとか考えないでいい
KZGいらないせつ

# BlobにProofを書き込む

128kBまでしか書き込めないはずなので

- base64でエンコード
- DAS的に圧縮
圧縮自体はしてない
送信は一部だけでよく、コミュニケーションコスト落とせる
検証は削れてても誤り訂正復元bできる

# EL-CL
 zkel vole prover作る
or
ELのexecute叩く

シーケンス
ブロック生成
Proof生成

dasをvoleの検証、圧縮につかう
elはgethみたいなもの
zkel何が嬉しい？
