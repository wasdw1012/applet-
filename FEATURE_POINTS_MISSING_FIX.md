# 特征点标签丢失问题诊断

## 问题描述
生成的 DG2 文件缺少特征点标签（0x92），导致验证失败。

## 可能的原因

### 1. dlib 模型文件缺失
检查是否存在 `shape_predictor_68_face_landmarks.dat` 文件：
```bash
ls -la shape_predictor_68_face_landmarks.dat
```

如果不存在，需要下载：
```bash
wget http://dlib.net/files/shape_predictor_68_face_landmarks.dat.bz2
bunzip2 shape_predictor_68_face_landmarks.dat.bz2
```

### 2. 人脸检测失败
如果输入图像中未检测到人脸，特征点检测会返回空列表。运行时会看到：
```
分析: ✗ 未在图像中检测到人脸。
```

### 3. 依赖库问题
确保安装了必要的库：
```bash
pip install dlib opencv-python
```

## 诊断步骤

### 1. 使用检查脚本
```bash
python check_feature_points.py DG2.bin
```

这会显示：
- DG2 文件中是否包含 0x92 标签
- 各个标签的位置

### 2. 检查生成日志
运行 `gen_dg2.py` 时注意以下输出：
- `分析: 正在检测面部特征点...`
- `分析: ✓ 检测到瞳孔中心: 左(X,Y), 右(X,Y)` - 成功
- `分析: ✗ 未在图像中检测到人脸。` - 失败
- `分析: ✗ 特征点检测时发生错误: ...` - 异常

### 3. 测试不带特征点检测
如果需要临时跳过特征点检测，可以修改 `gen_dg2.py`：

在第 460 行附近，将：
```python
feature_points = detect_facial_feature_points(numpy_image_for_detection)
```

改为：
```python
# feature_points = detect_facial_feature_points(numpy_image_for_detection)
feature_points = []  # 临时跳过特征点检测
```

## 解决方案

### 方案 1：确保 dlib 正常工作
1. 下载模型文件
2. 确保图像包含清晰的正面人脸
3. 图像尺寸不要太小（建议至少 300x400）

### 方案 2：手动添加测试特征点
如果只是为了测试，可以在第 460 行后添加：
```python
# 手动添加测试特征点
if not feature_points:
    feature_points = [
        {'type': 0x03, 'x': 100, 'y': 150},  # 左眼
        {'type': 0x04, 'x': 200, 'y': 150}   # 右眼
    ]
```

## 验证修复

修复后，再次运行：
```bash
python gen_dg2.py your_image.jpg
python check_feature_points.py DG2.bin
```

应该看到：
```
找到特征点标签(0x92)在位置: [XXX]
```