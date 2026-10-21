# 固定代码签名与升级授权

更新日期：2026-10-21。本文描述 v0.2.5 Build 8 的构建选项。该版本公开安装包仍采用 ad-hoc 签名，未经过 Apple 公证；固定证书支持不会自动给下载包补签名，也不会替换当前本机应用。

## 选择证书

对于准备通过 GitHub 分发安装包的 Surge CC，建议加入 **Apple Developer Program**，使用 **Developer ID Application** 证书。个人会员即可；Apple 公布的年费为 99 USD，实际价格按注册地区显示。证书申请属于会员能力，不需要购买 Enterprise 会员或上架 Mac App Store。[会员说明](https://developer.apple.com/help/account/membership/program-enrollment/)

`Developer ID Application` 用于签署 `.app`；`Developer ID Installer` 用于 `.pkg` 安装程序。当前 `.app` + ZIP 分发不需要 Installer 证书。[证书类型与申请](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/)

仅在自己管理的 Mac 上使用时，可以评估保留同一套本地自签代码签名证书；它与 `codesign --sign -` 的 ad-hoc 签名不同。但本地证书不获得 Developer ID 的发行信任，也不能替代 Apple 公证。实际权限延续仍要在目标系统验证，不能承诺创建一个证书就永久保留所有权限。[Apple 对自签证书的说明](https://developer.apple.com/library/archive/technotes/tn2206/)

## 申请 Developer ID Application

1. 使用开启双重认证的 Apple 账号，以真实法律姓名与联系方式申请[个人会员](https://developer.apple.com/programs/enroll/)。若由公司发行，使用对应的组织会员；组织注册有法律实体与 D-U-N-S 等额外要求。
2. 会员生效后，在负责签名的 Mac 上通过“钥匙串访问 → 证书助理 → 从证书颁发机构请求证书”生成 CSR，选择存储到磁盘。私钥保留在本机钥匙串中。[CSR 官方步骤](https://developer.apple.com/help/account/certificates/create-a-certificate-signing-request/)
3. 用 Account Holder 身份进入 Apple Developer 的 Certificates, Identifiers & Profiles，新增 **Developer ID Application**，按页面要求提交 CSR。
4. 下载 `.cer` 并在生成 CSR 的同一台 Mac 导入；在钥匙串“我的证书”中确认它关联私钥。只有 `.cer` 文件而没有对应私钥，不能完成签名。
5. 本机执行 `security find-identity -v -p codesigning`，确认存在有效的 `Developer ID Application` 身份。选定它后记录证书指纹，后续保持同一个团队、应用标识和兼容的签名要求。

个人签名证书会包含开发者身份信息，签名包的接收者可以检查证书中的开发者名称与 Team ID。若希望以公司身份发行，应在申请前确定发行主体，而不是发布后再切换。

私钥、`.p12` 导出包、导出密码及公证凭据不得放进公开仓库。CSR 也可能包含姓名、邮箱，只提交给预定的证书颁发机构。项目不会自动创建、导入证书或修改钥匙串信任设置。

## 使用固定证书构建

在项目目录执行；将占位符替换为本机选定证书的 40 位 SHA-1 指纹：

```sh
SURGE_CC_SIGNING_IDENTITY='证书的40位SHA1指纹' \
SURGE_CC_DIST_DIR="$PWD/.local/signed-candidate" \
./scripts/build-app.sh
```

- 也可传证书完整精确名称；建议使用指纹，避免同名证书歧义。证书指纹用于标识证书，不是文件完整性校验算法的选择。
- 构建先校验身份存在且唯一，再签名；身份缺失、签名或验证失败时停止，不退回 ad-hoc。
- 保持 `CFBundleIdentifier=local.surgecc.app`。正常升级时不随意更换团队、证书类型或应用标识；证书续期也应先检验签名要求是否兼容。
- 所有代码、图标与资源在签名前放入 bundle；签名后不再复制 Python 文件、修改 Info.plist 或写入缓存。
- 指定新输出目录构建候选包。构建脚本不会替换正在使用的应用，也不会修改系统权限。
- 未设置 `SURGE_CC_SIGNING_IDENTITY` 时仍允许开发用 ad-hoc 构建，但会明确警告其不能可靠保留跨版本授权。不要将这种开发包覆盖已经授权的证书签名安装版。

## 升级前验证签名身份

获得第一个证书签名版本后，每次更新先运行只读预检：

```sh
python3 scripts/check-signing-continuity.py \
  '/path/to/installed/Surge CC.app' \
  "$PWD/.local/signed-candidate/Surge CC.app" --json
```

脚本验证两包的签名、应用标识，以及新旧包是否双向满足对方的 designated requirement。成功退出码为 0；不兼容、ad-hoc 或无法核实时为 2。它不修改输入包、钥匙串或 TCC 数据库，也不自动安装。

这是签名连续性验证，不是查询或承诺系统的权限状态。首次从 ad-hoc 迁移到固定证书会报告不兼容，通常需要为新身份重新授权一次。将首次迁移作为单独步骤处理；后续升级只有预检通过再替换，并复查必要权限。[Apple 对签名身份与授权的说明](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)

如果失败，不要把要求放宽为仅比较应用名称或 bundle ID，也不要修改 TCC 数据库绕过系统授权。

## GitHub 公开发行与公证

固定签名解决代码身份连续性；公证是另一项发布步骤。Developer ID 构建已请求安全时间戳，但当前构建选项**没有自动启用 Hardened Runtime 或提交公证**。

首次公证发行前，还需核对 Hardened Runtime、必要的 Apple Events 权限与签名资源，验收终端打开、专用浏览器及 OAuth 流程，再通过 Apple 公证并装订票据。不要把“签名验证通过”写成“已公证”或“所有 Mac 都能直接打开”。[Apple 公证说明](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)

当前已有的未签名/临时签名安装包不会因为申请了证书而自动升级；应在新包完成验收后另行发布。
