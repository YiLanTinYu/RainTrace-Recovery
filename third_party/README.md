# 成熟开源恢复引擎集成基线

## The Sleuth Kit 4.15.0

- 上游：https://github.com/sleuthkit/sleuthkit
- 发布：https://github.com/sleuthkit/sleuthkit/releases/tag/sleuthkit-4.15.0
- 用途：作为 NTFS、exFAT、FAT 等文件系统元数据解析与按元数据地址恢复的主引擎。
- 集成方式：雨痕通过无 Shell 插值的 `fls`/`icat` 进程边界调用；源路径只作为读取参数，目标路径由雨痕控制。
- Windows 包 SHA-256：`c2ebab8105b893d97bd8ce35b88e01985e2a106efc97f03adf95840a631b20ce`
- 源码包 SHA-256：`3a8c1e7d18a9b81f3e5e8aa78313974aceaafc6e051d636bc92cd7168286eca9`
- 完整源码：`third_party/sleuthkit-4.15.0`；原始归档：`third_party/downloads/sleuthkit-4.15.0.tar.gz`。

雨痕负责磁盘枚举、只读策略、目标盘隔离、中文编码适配、逻辑去重、结果筛选、恢复后结构校验和界面；TSK 负责成熟的文件系统解释。旧扫描器暂时仅用于 TSK 失败回退和 TSK 不提供的旧元数据深搜，待真实镜像对照测试覆盖后逐步退出。

## TestDisk / PhotoRec 7.2

- 上游：https://github.com/cgsecurity/testdisk
- 稳定版本：v7.2
- 固定提交：281be432dd79121e08e0898887a9ee1f30fb3e96
- 许可证：GPL-2.0-or-later，原文见 `testdisk/COPYING`

## 雨痕采用范围

1. PhotoRec 文件签名数据库和格式级完整性校验。
2. `freespace` 未分配空间扫描，避免把活动文件中的图标、缩略图反复列为删除候选。
3. PhotoRec 恢复文件输出、会话与日志，由雨痕 WPF 界面负责配置、启动、监控、结果分类和预览。
4. 雨痕现有 NTFS/exFAT/FAT32 元数据恢复继续用于保留原文件名；PhotoRec 作为无原名兜底。

## 不采用

- 不以 QPhotoRec 替换雨痕品牌和 WPF 界面。
- 不让 PhotoRec 写入源介质；目标目录仍必须位于其他物理磁盘。
- 不把“整盘特征命中”默认展示成删除文件，默认使用 `freespace`。
