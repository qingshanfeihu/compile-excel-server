# 无跨机器墙钟依赖的请求协议

所有者授权 gw-no-wallclock：仅本地提交；不推送、打标签、发布或部署。所有检查使用合成工作簿、假框架、假设备与回环服务；未读取所有者环境配置、钥匙串或接触真实系统；测试配置均为临时合成。

## 变更

- 请求身份账本仍是至多一次的依据。新请求带 request_id、dispatch_sequence（1 至 2^53-1 的整数）、sequence_scope（执行器身份），与认证主体一起隔离序号流。旧 not_after 原样记录，回执说明 not_after_ignored；它不再要求为 UTC 截止，也不与网关墙钟比较。
- 已登记 request_id 的重复提交拒绝，stage=duplicate；只读 case_request 查原记录。原任务不再启动。原记录仍处理中时 reached_device=null，不能猜为未触达。冲突保持拒绝，不泄露别的主体记录。
- 独立 SQLite 日志为每个主体/序号流保存只增 sequence_floor；不大于它或已使用的序号不能新建请求。显式 journal-gc 回收，待处理/未知状态阻止回收。最小 id 墓碑保留，防止同 id 换新序号重新执行。旧无序号历史不猜测迁移序号，永久保留。
- 原按天的 gc 不再删除请求账本，也不会因旧截止到期而释放关联文件；先按序号核对与回收，再做普通文件清理。回收已移除历史时 stage=collected、reached_device=null；这种拒绝不是原请求未执行的证明。
- 网关租约以本机单调时间计算相对 TTL，单调截止绑定操作系统启动身份；同一系统启动内可跨进程恢复，系统重启或旧式墙钟租约失效。墙钟只写 acquired_at/expires_at 等记录；expires_in_s 来自单调时钟。
- 回执、结果、journal_since、gc_before、gateway_time 等时刻只作记录；跨机器时间顺序及查空均不能证明未执行。截止由 Hub 在真正发送前用自己的时钟判断。

使用及升级说明见 gateway.md。旧 request_id/not_after 的同键缓存回放、墙钟过期和时间回收测试已按上述所有者设计更正，未删跳测试。锁竞争、崩溃恢复、目录归属、请求主体、审计链和结果保留覆盖仍保留。

## 验证

最终 `python -m pytest tests/ -q -rs`：355 过，0 失败，15 项因外部 skills/InfoTest 等条件缺失而跳过，没有强行启用这些外部入口。新增覆盖正负 7 小时偏差、无绝对截止、重复 id、序号回收线与持久恢复、单调 TTL、系统启动身份和回收 CLI。测试至多两个工作进程，本仓 pytest 串行。
