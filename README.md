# 奶龙群组导航：GitHub 自动构建模板

纯静态网站，不需要 PHP、数据库或常驻服务器。正式数据存储在 `public/data/groups.json`，GitHub Actions 负责校验、构建，并部署到 GitHub Pages。另附本地群组 JSON 录入工具。

## 功能
- 响应式首页、关键词搜索、类型筛选、群组详情、复制群号。
- `tools/group-editor.html`：导入 JSON、新增、编辑、删除、复制记录、导出 JSON。
- 构建时校验必填字段、群号格式、类型、状态、重复 ID；重复群号仅警告，交由人工核验。
- GitHub Issue 投稿模板：`.github/ISSUE_TEMPLATE/group-submission.yml`。
- 推送到 `main` 后由 Actions 自动构建和发布 GitHub Pages。

## 使用
1. 将本项目所有文件上传到 GitHub 仓库的 `main` 分支。
2. 仓库 Settings → Pages → Build and deployment → Source 选择 **GitHub Actions**。
3. 推送到 `main` 后，在 Actions 查看构建和部署结果。
4. 本地开发需要 Node.js 22+：`npm install`、`npm run dev`；构建验证：`npm run build`。

## 修改数据
1. 打开 `tools/group-editor.html`。若浏览器不允许页面读取本地 JSON，请在项目根目录运行 `python -m http.server 8000`，再访问 `http://localhost:8000/tools/group-editor.html`。
2. 导入 `public/data/groups.json`，修改后点击“导出 groups.json”。
3. 用导出的文件替换仓库中的 `public/data/groups.json`，提交到 GitHub。
4. Actions 自动校验和发布。

工具不会自动写入 GitHub，也不会上传数据。请勿在前端页面中放 GitHub Token。投稿通过 GitHub Issues 收集，管理员人工核验后修改正式 JSON。

## 数据字段
`id` 唯一 ID；`school` 学校/组织；`schoolAliases` 搜索别名数组；`name` 群名；`qq` 群号字符串；`type` 奶龙/奶蛙/联合会/其他；`intro` 简介；`rules` 群规；`joinUrl` 可选 HTTPS 链接；`status` active/paused/dissolved/pending；`verifiedAt` 核验日期；`updatedAt` 最后更新日期。

## 部署路径注意
此模板默认站点部署在域名根路径（如自定义域名或 `username.github.io`）。若使用 `https://username.github.io/repo-name/` 这种项目子路径，需要配置 Vite `base` 并调整数据请求路径。`提交群组` 按钮中的 `OWNER/REPO` 也需要替换成你的 GitHub 用户名和仓库名。

模板中的群组记录仅为演示样例，并非完整名单或有效性证明。发布前应导入和核验实际数据。
