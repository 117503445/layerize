# Layerize 项目架构与设计

## 概述

Layerize 是一个用于构建 OCI 镜像的工具，它通过向现有基础镜像添加新的层来创建新镜像。该工具可以直接从文件映射创建镜像层，无需 Dockerfile。项目采用模块化设计，将功能划分为多个包，便于维护和扩展。

## 整体架构

```
┌─────────────────┐
│     main.go     │
│  (程序入口点)    │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  builder 包     │
│ (构建核心逻辑)   │
└─────────┬───────┘
          │
    ┌─────┴─────┐
    ▼           ▼
┌────────┐  ┌──────────┐
│registry│  │manifest  │
│(镜像仓库│  │(清单处理)│
│ 交互)   │  │          │
└────────┘  └──────────┘
    │           │
    ▼           ▼
┌────────┐  ┌──────────┐
│ utils  │  │  types   │
│(工具函数│  │ (类型定义)│
│ 和辅助) │  │          │
└────────┘  └──────────┘
```

## 模块设计

### 1. main.go - 程序入口

主要职责：
- 初始化日志系统
- 加载环境变量配置
- 创建测试文件映射
- 调用构建器执行镜像构建
- 验证构建结果

### 2. builder 包 - 构建核心逻辑

主要职责：
- 将文件映射转换为 tar 格式
- 压缩为 tar.gz 格式
- 计算层的 SHA256 摘要
- 与镜像仓库交互，上传层和配置
- 更新并上传镜像清单

关键函数：
- `BuildImageFromMap`: 从文件映射构建镜像
- `BuildImage`: 执行完整的镜像构建流程

构建流程（流式传输，无需解压与落盘）：
1. 将文件映射转换为 tar 数据
2. 压缩为 tar.gz 格式
3. 计算未压缩 `diff.tar` 的 SHA256（作为 config 的 diffID），以及压缩 `diff.tar.gz` 的 SHA256（作为 manifest 的 layer digest）
4. 使用 `io.Reader` 流式上传压缩层（无需临时文件）
5. 获取基础镜像配置并更新（将 `diff_ids` 追加 `sha256:<DiffTarSHA256>`）
6. 上传更新后的配置
7. 获取基础镜像清单并更新（将 layer `digest` 设为 `sha256:<DiffTarGzSHA256>`，`size` 为压缩大小）
8. 上传更新后的清单

### 3. registry 包 - 镜像仓库交互

主要职责：
- 与 OCI 镜像仓库进行交互
- 处理认证和令牌管理
- 上传和下载镜像层、配置和清单

关键组件：
- `Client`: 镜像仓库客户端，包含认证和缓存机制
- `Token`: 认证令牌结构
- 认证机制：支持基础认证和 Bearer Token 认证

关键函数：
- `UploadLayerWithClient`: 上传镜像层
- `GetConfigWithAuth`: 获取镜像配置
- `UploadConfigWithClient`: 上传镜像配置
- `UploadManifest`: 上传镜像清单

认证流程：
1. 如果提供了用户名和密码，初始请求包含基础认证信息
2. 当收到 401 响应且包含 WWW-Authenticate 头部时，解析该头部并获取 Bearer Token
3. 如果获取 Bearer Token 失败，回退到基础认证方式
4. 支持令牌缓存，避免重复认证请求

### 4. manifest 包 - 清单处理

主要职责：
- 处理 OCI 和 Docker 镜像清单
- 更新清单以添加新层

关键组件：
- `DockerManifestV2`: Docker v2 清单结构
- `OCIManifest`: OCI 清单结构
- `ManifestConfig`: 配置部分结构
- `ManifestLayer`: 层信息结构

关键函数：
- `UpdateManifest`: 向清单添加新层
- `UpdateOCIConfig`: 更新 OCI 配置以添加新层

### 5. utils 包 - 工具函数

主要职责：
- 提供通用工具函数

关键函数：
- `MapToTar`: 将文件映射转换为 tar 数据
- `CalculateDataSHA256`: 计算数据的 SHA256 摘要
- `CalculateFileSHA256`: 计算文件的 SHA256 摘要
- `DecompressGzipData`: 解压缩 gzip 数据

### 6. types 包 - 类型定义

主要职责：
- 定义项目中使用的结构体类型

关键类型：
- `Auth`: 认证信息结构
- `BuildImageParams`: 构建参数结构

### 7. validator 包 - 镜像验证

主要职责：
- 验证构建的镜像是否正确

关键函数：
- `ValidateBuiltImage`: 验证构建的镜像

验证流程：
1. 使用 podman 拉取构建的镜像
2. 检查新添加的文件是否存在且内容正确
3. 验证删除的文件确实不存在

## BuildImageFromMap 流程详解

`BuildImageFromMap` 函数是整个项目的核心函数之一，负责将文件映射转换为 OCI 镜像。下面是该函数的详细执行流程和关键日志信息：

### 1. 准备阶段

流程开始时，函数接收以下参数：
- `ctx`: 上下文对象
- `files`: 文件映射 (map[string][]byte)
- `targetImage`: 目标镜像引用（`repository[:tag]`）
- `targetAuth`: 目标镜像仓库认证信息
- `baseImage`: 基础镜像引用（`repository[:tag]`）
- `baseImageAuth`: 基础镜像仓库认证信息
（不再单独传递标签，若未提供标签，默认 `latest`）

### 2. 创建 TAR 数据

首先，使用 `utils.MapToTar` 函数将文件映射转换为 TAR 格式数据：

```
tarData, err := utils.MapToTar(ctx, files)
```

关键日志：
- 错误情况：`"Failed to create tar data"`

### 3. 压缩为 TAR.GZ

将 TAR 数据压缩为 GZIP 格式：

```go
var gzData bytes.Buffer
gzWriter := gzip.NewWriter(&gzData)
if _, err := gzWriter.Write(tarData); err != nil {
    // 错误处理
}
if err := gzWriter.Close(); err != nil {
    // 错误处理
}
```

关键日志：
- 错误情况：`"Failed to write gzip data"`、`"Failed to close gzip writer"`

### 4. 调用 BuildImage

将压缩后的数据与必要元信息包装为参数并调用 [BuildImage](file:///workspace/pkg/builder/builder.go) 函数：

```go
params := types.BuildImageParams{
    BaseImage:        baseImage,       // e.g. "namespace/repo:latest"
    BaseImageAuth:    baseImageAuth,
    DiffTarGzReader:  bytes.NewReader(gzData.Bytes()),
    DiffTarLen:       int64(gzData.Len()),
    DiffTarSHA256:    diffTarSHA256,    // 未压缩 tar 的 SHA256（diffID）
    DiffTarGzSHA256:  diffTarGzSHA256,  // 压缩层 blob 的 SHA256
    TargetImage:      targetImage,     // e.g. "namespace/repo:tag"
    TargetAuth:       targetAuth,
}

return BuildImage(ctx, params)
```

### 5. BuildImage 执行流程

[BuildImage](file:///workspace/pkg/builder/builder.go) 函数执行完整的镜像构建过程，包含以下关键步骤和日志：

#### 步骤 0: 初始化和记录开始信息

关键日志：
```json
{
  "phase": "build",
  "step": 0,
  "base_image": "镜像名称",
  "target_image": "目标镜像名称",
  "base_tag": "基础标签",
  "target_tag": "目标标签",
  "diff_tar_gz_len": 压缩数据长度,
  "message": "Start image building process"
}
```

#### 步骤 1: 使用提供的压缩层大小

关键日志：
```json
{
  "phase": "build",
  "step": 1,
  "compressed_size": 压缩大小,
  "message": "Using provided compressed layer size"
}
```

#### 步骤 2: 流式上传压缩层到目标镜像仓库

关键日志：
```json
{
  "phase": "build",
  "step": 2,
  "message": "Uploaded compressed layer to target image registry"
}
```

#### 步骤 3: 获取基础镜像配置

关键日志：
```json
{
  "phase": "build",
  "step": 3,
  "configSize": 配置大小,
  "message": "Obtained base image config"
}
```

Debug 级别日志还会包含完整的配置内容。

#### 步骤 4: 更新 OCI 配置，添加新的层 diffID

关键日志：
```json
{
  "phase": "build",
  "step": 4,
  "updatedConfigSize": 更新后配置大小,
  "message": "Updated base image config, added new layer diffID"
}
```

Debug 级别日志还会包含更新后的配置内容。

#### 步骤 5: 上传更新后的配置

关键日志：
```json
{
  "phase": "build",
  "step": 5,
  "config_digest": "配置摘要",
  "message": "Uploaded updated config"
}
```

#### 步骤 6: 获取基础镜像清单

关键日志：
```json
{
  "phase": "build",
  "step": 6,
  "contentType": "内容类型",
  "manifestSize": 清单大小,
  "message": "Obtained base image manifest"
}
```

Debug 级别日志还会包含完整的清单内容。

#### 步骤 7: 更新清单，指向新配置和层

关键日志：
```json
{
  "phase": "build",
  "step": 7,
  "updatedManifestSize": 更新后清单大小,
  "message": "Updated manifest, pointing to new config and layer"
}
```

Debug 级别日志还会包含更新后的清单内容。

#### 步骤 8: 上传更新后的清单到目标仓库

关键日志：
```json
{
  "phase": "build",
  "step": 8,
  "repository": "仓库名称",
  "reference": "引用标签",
  "message": "Uploaded updated manifest to target registry"
}
```

## 设计原则

### 1. 模块化设计

项目采用模块化设计，将功能划分为独立的包：
- 每个包都有明确的职责
- 包之间通过定义良好的接口进行交互
- 便于测试和维护

### 2. 单一职责原则

每个函数和包都有明确的单一职责：
- builder 包负责构建流程
- registry 包负责镜像仓库交互
- manifest 包负责清单处理
- utils 包提供通用工具函数

### 3. 错误处理

- 使用结构化日志记录错误信息
- 为每个错误提供清晰的上下文信息
- 适当使用包装错误以保留错误链

### 4. 认证缓存

- 实现令牌缓存机制以提高性能
- 检查令牌过期时间，避免使用过期令牌
- 添加缓冲时间以避免竞态条件

## 数据流

1. 用户提供文件映射和基础镜像信息
2. builder 包将文件映射转换为 tar.gz 格式
3. registry 包与镜像仓库交互，上传层和配置
4. manifest 包更新清单以包含新层
5. registry 包上传更新后的清单
6. validator 包验证构建的镜像

## 扩展性考虑

### 1. 支持多种镜像格式

- 当前支持 OCI 和 Docker v2 格式
- 通过检测 MediaType 自动处理不同格式

### 2. 认证机制

- 支持基础认证和 Bearer Token 认证
- 可扩展以支持其他认证方式

### 3. 日志系统

- 使用 zerolog 提供结构化日志
- 便于调试和监控

## 性能优化

### 1. 令牌缓存

- 缓存认证令牌以避免重复认证请求
- 检查令牌过期时间以确保有效性

### 2. 临时文件处理

- 使用临时文件处理大层数据
- 及时清理临时文件以释放空间

## 安全考虑

### 1. 认证安全

- 支持多种认证方式
- 安全处理认证凭据
- 避免在日志中记录敏感信息

### 2. 数据完整性

- 使用 SHA256 摘要验证数据完整性
- 确保上传和下载的数据一致

## 未来改进方向

1. 支持更多镜像仓库（当前主要针对阿里云镜像仓库）
2. 增加更多测试用例
3. 支持并行上传多个层
4. 增加更多的错误恢复机制
5. 支持更多 OCI 镜像特性