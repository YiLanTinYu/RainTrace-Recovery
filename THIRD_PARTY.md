# 第三方项目与许可证

- The Sleuth Kit 4.15.0: https://github.com/sleuthkit/sleuthkit — 多许可证，随上游文件分别适用 IBM/CPL、Apache-2.0、BSD、MIT、GPL 等
  - 官方 Windows 包和完整源码均已固定到 4.15.0；下载归档 SHA-256 已与官方 Release 值核对。
  - 发布包携带上游 `licenses`、README 和 `SOURCE.txt`；项目内保留完整对应源码。
  - 雨痕调用 `fls` 扫描已删除元数据，调用 `icat` 按元数据地址恢复，不修改源介质。
- TestDisk / PhotoRec 7.2: https://github.com/cgsecurity/testdisk — GPL-2.0-or-later
  - 官方源码已引入 `third_party/testdisk`。
  - 固定标签：`v7.2`；提交：`281be432dd79121e08e0898887a9ee1f30fb3e96`。
  - 上游许可证原文：`third_party/testdisk/COPYING`。
  - 官方 Windows 64 位包 SHA-256：`E97E203CE77B6B1A3A37D01BECCF069DC6C4632B579FFBB82AE739CDDA229F38`。
  - 雨痕将以 PhotoRec 的成熟文件识别、未分配空间扫描和损坏文件校验能力替换自研弱特征扫描。
- QPhotoRec：TestDisk 项目中的 Qt 图形界面；本项目保留雨痕 WPF 界面，不直接复用其界面代码。
- DMDE: https://dmde.com/ — 商业/免费限制使用，作为功能对照，不含其代码
- R-Studio: https://www.r-studio.com/ — 商业软件，作为交互与恢复策略参考，不含其代码

## GPL 合规边界

TestDisk/PhotoRec 已进入本项目源码树。后续包含 PhotoRec 二进制或派生代码的雨痕发行包必须按 GPL v2 或更高版本提供许可证、对应源码、修改说明和获取源码方式。雨痕不再声明其恢复引擎完全为独立实现。
