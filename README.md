# Layerize

Layerize 是一个用于构建 OCI 镜像的工具，它通过向现有基础镜像添加新的层来创建新镜像。该工具可以直接从文件映射创建镜像层，无需 Dockerfile。

## 功能特性

- 从文件映射直接构建 OCI 镜像
- 支持添加新文件和删除现有文件（通过白名单机制）
- 自动处理镜像层压缩和上传
- 支持阿里云镜像仓库
- 完整的构建过程日志记录

## 工作原理

Layerize 通过以下步骤构建镜像：

1. 将文件映射转换为 tar 格式
2. 压缩为 tar.gz 格式
3. 计算层的 SHA256 摘要（diffID 和压缩层摘要）
4. 将层上传到目标镜像仓库
5. 获取基础镜像配置并更新以包含新层
6. 更新镜像清单以指向新配置和层
7. 将更新后的清单上传到目标仓库

## 安装要求

- Go 1.24 或更高版本
- Podman（用于镜像验证）

## 环境变量配置

在使用 Layerize 之前，需要配置以下环境变量：

```
username=your_username
password=your_password
```

这些变量可以在 [.env](.env) 文件中设置。

## 使用方法

### 直接运行

```bash
go run .
```

### 使用 Docker Compose

```bash
docker-compose up dev
```

## 项目结构

```
.
├── assets           # 资源文件
├── cmd              # 命令行程序入口
├── internal         # 核心代码
│   ├── builder      # 镜像构建逻辑
│   ├── config       # 配置处理
│   ├── manifest     # 清单处理
│   ├── registry     # 镜像仓库交互
│   ├── types        # 类型定义
│   ├── utils        # 工具函数
│   └── validator    # 镜像验证
├── .env             # 环境变量配置
├── go.mod           # Go 模块定义
├── main.go          # 主程序入口
├── Taskfile.yml     # 任务定义
└── compose.yaml     # Docker Compose 配置
```

## 验证机制

构建完成后，Layerize 使用 Podman 验证生成的镜像：

1. 拉取新构建的镜像
2. 检查新添加的文件是否存在且内容正确
3. 验证删除的文件确实不存在
