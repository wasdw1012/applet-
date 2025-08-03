#!/usr/bin/env python3
"""
十六进制分析器 GUI界面
基于tkinter的专业十六进制编辑器界面
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.font as tkfont
import os
import sys
import threading
from typing import Optional, List, Tuple, Dict, Any
import queue

# 导入核心分析模块
from hex_pro import HexAnalyzer, TLVField, Colors as TerminalColors

# 尝试导入拖放支持
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False
    print("提示: 安装 tkinterdnd2 以启用拖放功能")
    print("pip install tkinterdnd2")

# GUI配色方案
class Theme:
    # 背景色
    BG_PRIMARY = '#1e1e1e'      # 主背景
    BG_SECONDARY = '#252526'     # 次要背景
    BG_TERTIARY = '#2d2d30'      # 第三背景
    BG_HOVER = '#3e3e42'         # 悬停背景
    
    # 前景色
    FG_PRIMARY = '#cccccc'       # 主文字
    FG_SECONDARY = '#969696'     # 次要文字
    FG_ACCENT = '#569cd6'        # 强调色（蓝色）
    FG_SUCCESS = '#608b4e'       # 成功色（绿色）
    FG_WARNING = '#d7ba7d'       # 警告色（黄色）
    FG_ERROR = '#f44747'         # 错误色（红色）
    
    # 功能色
    HEX_ADDRESS = '#858585'      # 地址颜色
    HEX_VALUE = '#d4d4d4'        # 十六进制值
    ASCII_VALUE = '#608b4e'      # ASCII值
    SELECTION = '#264f78'        # 选中背景
    HIGHLIGHT = '#513d2b'        # 搜索高亮
    
    # 边框
    BORDER = '#3e3e42'           # 边框颜色
    BORDER_FOCUS = '#007acc'     # 焦点边框

class HexView(tk.Frame):
    """十六进制视图组件"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)
        
        self.analyzer = None
        self.offset = 0
        self.bytes_per_line = 16
        self.lines_per_page = 20
        self.selection_start = None
        self.selection_end = None
        self.search_results = []
        self.current_search_index = -1
        
        self._setup_ui()
        self._setup_bindings()
        
    def _setup_ui(self):
        """设置UI"""
        # 创建Canvas和滚动条
        self.canvas = tk.Canvas(
            self, 
            bg=Theme.BG_PRIMARY,
            highlightthickness=0,
            cursor="xterm"
        )
        
        self.v_scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._on_scroll)
        self.canvas.configure(yscrollcommand=self.v_scrollbar.set)
        
        # 布局
        self.canvas.pack(side="left", fill="both", expand=True)
        self.v_scrollbar.pack(side="right", fill="y")
        
        # 字体设置
        self.font_family = "Consolas" if sys.platform == "win32" else "Courier"
        self.font_size = 11
        self.font = tkfont.Font(family=self.font_family, size=self.font_size)
        
        # 计算字符宽度和高度
        self.char_width = self.font.measure("0")
        self.line_height = self.font.metrics("linespace") + 2
        
        # 列宽计算
        self.addr_width = 10 * self.char_width  # "00000000: "
        self.hex_width = (self.bytes_per_line * 3 + 1) * self.char_width
        self.ascii_width = self.bytes_per_line * self.char_width
        self.total_width = self.addr_width + self.hex_width + self.ascii_width + 4 * self.char_width
        
    def _setup_bindings(self):
        """设置事件绑定"""
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Control-c>", self._on_copy)
        self.canvas.bind("<Control-a>", self._on_select_all)
        
    def set_analyzer(self, analyzer: HexAnalyzer):
        """设置分析器"""
        self.analyzer = analyzer
        self.offset = 0
        self._update_scrollbar()
        self.refresh()
        
    def refresh(self):
        """刷新显示"""
        if not self.analyzer:
            return
            
        self.canvas.delete("all")
        
        # 计算可见行数
        canvas_height = self.canvas.winfo_height()
        if canvas_height <= 1:
            canvas_height = 500  # 默认高度
        visible_lines = max(1, canvas_height // self.line_height)
        
        # 绘制每一行
        for line_idx in range(visible_lines):
            line_offset = self.offset + line_idx * self.bytes_per_line
            if line_offset >= len(self.analyzer.data):
                break
                
            self._draw_line(line_idx, line_offset)
            
    def _draw_line(self, line_idx: int, offset: int):
        """绘制一行"""
        y = line_idx * self.line_height + 5
        
        # 地址
        addr_text = f"{offset:08X}: "
        self.canvas.create_text(
            5, y,
            text=addr_text,
            anchor="nw",
            font=self.font,
            fill=Theme.HEX_ADDRESS
        )
        
        # 十六进制和ASCII
        hex_x = self.addr_width
        ascii_x = self.addr_width + self.hex_width + 2 * self.char_width
        
        hex_parts = []
        ascii_text = ""
        
        for i in range(self.bytes_per_line):
            byte_offset = offset + i
            if byte_offset >= len(self.analyzer.data):
                break
                
            byte_val = self.analyzer.data[byte_offset]
            
            # 检查是否被选中
            is_selected = (self.selection_start is not None and 
                          self.selection_start <= byte_offset <= self.selection_end)
            
            # 检查是否是搜索结果
            is_highlighted = any(start <= byte_offset < end 
                               for start, end in self.search_results)
            
            # 十六进制
            hex_text = f"{byte_val:02X}"
            hex_color = Theme.HEX_VALUE
            bg_color = None
            
            if is_selected:
                bg_color = Theme.SELECTION
            elif is_highlighted:
                bg_color = Theme.HIGHLIGHT
                
            if bg_color:
                # 绘制背景
                self.canvas.create_rectangle(
                    hex_x + i * 3 * self.char_width,
                    y - 2,
                    hex_x + (i * 3 + 2) * self.char_width,
                    y + self.line_height - 2,
                    fill=bg_color,
                    outline=""
                )
                
            self.canvas.create_text(
                hex_x + i * 3 * self.char_width,
                y,
                text=hex_text,
                anchor="nw",
                font=self.font,
                fill=hex_color
            )
            
            # 每8个字节额外空格
            if i == 7:
                hex_x += self.char_width
                
            # ASCII
            if 32 <= byte_val < 127:
                ascii_char = chr(byte_val)
                ascii_color = Theme.ASCII_VALUE
            else:
                ascii_char = "."
                ascii_color = Theme.FG_SECONDARY
                
            if bg_color:
                # ASCII背景
                self.canvas.create_rectangle(
                    ascii_x + i * self.char_width,
                    y - 2,
                    ascii_x + (i + 1) * self.char_width,
                    y + self.line_height - 2,
                    fill=bg_color,
                    outline=""
                )
                
            self.canvas.create_text(
                ascii_x + i * self.char_width,
                y,
                text=ascii_char,
                anchor="nw",
                font=self.font,
                fill=ascii_color
            )
            
    def _update_scrollbar(self):
        """更新滚动条"""
        if not self.analyzer:
            return
            
        total_lines = (len(self.analyzer.data) + self.bytes_per_line - 1) // self.bytes_per_line
        visible_lines = max(1, self.canvas.winfo_height() // self.line_height)
        
        if total_lines <= visible_lines:
            self.v_scrollbar.set(0, 1)
        else:
            current_line = self.offset // self.bytes_per_line
            fraction = current_line / total_lines
            visible_fraction = visible_lines / total_lines
            self.v_scrollbar.set(fraction, fraction + visible_fraction)
            
    def _on_scroll(self, *args):
        """处理滚动条事件"""
        if not self.analyzer:
            return
            
        action = args[0]
        if action == "moveto":
            fraction = float(args[1])
            total_lines = (len(self.analyzer.data) + self.bytes_per_line - 1) // self.bytes_per_line
            target_line = int(fraction * total_lines)
            self.offset = target_line * self.bytes_per_line
            self.refresh()
        elif action == "scroll":
            delta = int(args[1])
            units = args[2]
            if units == "units":
                self.scroll_lines(delta)
            else:  # pages
                visible_lines = max(1, self.canvas.winfo_height() // self.line_height)
                self.scroll_lines(delta * visible_lines)
                
    def _on_mousewheel(self, event):
        """处理鼠标滚轮"""
        # Windows和macOS的滚轮事件不同
        if sys.platform == "darwin":
            delta = event.delta
        else:
            delta = -event.delta // 120
        self.scroll_lines(delta * 3)
        
    def scroll_lines(self, lines: int):
        """滚动指定行数"""
        if not self.analyzer:
            return
            
        new_offset = self.offset + lines * self.bytes_per_line
        max_offset = len(self.analyzer.data) - self.bytes_per_line
        self.offset = max(0, min(new_offset, max_offset))
        self._update_scrollbar()
        self.refresh()
        
    def goto_offset(self, offset: int):
        """跳转到指定偏移"""
        if not self.analyzer:
            return
            
        self.offset = (offset // self.bytes_per_line) * self.bytes_per_line
        self._update_scrollbar()
        self.refresh()
        
    def _get_byte_at_pos(self, x: int, y: int) -> Optional[int]:
        """获取鼠标位置对应的字节偏移"""
        line = y // self.line_height
        line_offset = self.offset + line * self.bytes_per_line
        
        # 检查是否在十六进制区域
        if self.addr_width <= x < self.addr_width + self.hex_width:
            rel_x = x - self.addr_width
            # 考虑每8字节的额外空格
            if rel_x < 8 * 3 * self.char_width:
                byte_idx = rel_x // (3 * self.char_width)
            else:
                rel_x -= self.char_width  # 减去额外空格
                byte_idx = rel_x // (3 * self.char_width)
                
            if 0 <= byte_idx < self.bytes_per_line:
                offset = line_offset + byte_idx
                if offset < len(self.analyzer.data):
                    return offset
                    
        # 检查是否在ASCII区域
        ascii_start = self.addr_width + self.hex_width + 2 * self.char_width
        if ascii_start <= x < ascii_start + self.ascii_width:
            byte_idx = (x - ascii_start) // self.char_width
            if 0 <= byte_idx < self.bytes_per_line:
                offset = line_offset + byte_idx
                if offset < len(self.analyzer.data):
                    return offset
                    
        return None
        
    def _on_click(self, event):
        """处理鼠标点击"""
        offset = self._get_byte_at_pos(event.x, event.y)
        if offset is not None:
            self.selection_start = offset
            self.selection_end = offset
            self.refresh()
            # 通知父窗口选择变化
            self.event_generate("<<SelectionChanged>>")
            
    def _on_drag(self, event):
        """处理拖动选择"""
        offset = self._get_byte_at_pos(event.x, event.y)
        if offset is not None and self.selection_start is not None:
            self.selection_end = offset
            self.refresh()
            
    def _on_copy(self, event):
        """复制选中内容"""
        if self.selection_start is None or self.selection_end is None:
            return
            
        start = min(self.selection_start, self.selection_end)
        end = max(self.selection_start, self.selection_end) + 1
        
        data = self.analyzer.data[start:end]
        hex_str = data.hex().upper()
        
        self.clipboard_clear()
        self.clipboard_append(hex_str)
        
    def _on_select_all(self, event):
        """全选"""
        if not self.analyzer:
            return
            
        self.selection_start = 0
        self.selection_end = len(self.analyzer.data) - 1
        self.refresh()
        
    def highlight_range(self, start: int, end: int):
        """高亮指定范围"""
        self.search_results = [(start, end)]
        self.current_search_index = 0
        self.goto_offset(start)
        
    def get_selection(self) -> Optional[Tuple[int, int]]:
        """获取当前选择范围"""
        if self.selection_start is None or self.selection_end is None:
            return None
        return (min(self.selection_start, self.selection_end),
                max(self.selection_start, self.selection_end) + 1)


class StructureTree(ttk.Treeview):
    """结构树视图"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        # 配置列
        self["columns"] = ("value", "offset", "length")
        self.heading("#0", text="标签")
        self.heading("value", text="值")
        self.heading("offset", text="偏移")
        self.heading("length", text="长度")
        
        # 列宽
        self.column("#0", width=200)
        self.column("value", width=150)
        self.column("offset", width=80)
        self.column("length", width=60)
        
        # 样式
        style = ttk.Style()
        style.configure("Treeview", 
                       background=Theme.BG_SECONDARY,
                       foreground=Theme.FG_PRIMARY,
                       fieldbackground=Theme.BG_SECONDARY)
        style.map("Treeview",
                 background=[('selected', Theme.SELECTION)])
        
    def load_tlv_fields(self, fields: List[TLVField], parent_item="", level=0):
        """加载TLV字段"""
        for field in fields:
            # 调试输出
            if level <= 2:
                print(f"{'  ' * level}GUI加载: Tag={field.tag_bytes.hex().upper()}, 子节点数={len(field.children)}")
            
            # 准备显示文本
            tag_text = f"{field.tag_bytes.hex().upper()} {field.tag_description}"
            
            # 值显示
            if field.parsed_value:
                value_text = str(field.parsed_value)[:50]
            elif field.value_type:
                value_text = f"[{field.value_type}]"
            elif len(field.value) <= 8:
                value_text = field.value.hex().upper()
            else:
                value_text = f"{field.value[:8].hex().upper()}..."
                
            # 插入节点
            item = self.insert(
                parent_item, "end",
                text=tag_text,
                values=(
                    value_text,
                    f"0x{field.offset:04X}",
                    f"{field.length}"
                ),
                tags=("truncated",) if field.is_truncated else ()
            )
            
            # 递归加载子节点
            if field.children:
                self.load_tlv_fields(field.children, item, level + 1)
                
        # 设置截断项的样式
        self.tag_configure("truncated", foreground=Theme.FG_ERROR)


class DetailPanel(ttk.Notebook):
    """详细信息面板"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        # 创建标签页
        self.parse_frame = tk.Frame(self, bg=Theme.BG_SECONDARY)
        self.properties_frame = tk.Frame(self, bg=Theme.BG_SECONDARY)
        self.interpreter_frame = tk.Frame(self, bg=Theme.BG_SECONDARY)
        
        self.add(self.parse_frame, text="解析")
        self.add(self.properties_frame, text="属性")
        self.add(self.interpreter_frame, text="数据解释器")
        
        self._setup_parse_tab()
        self._setup_properties_tab()
        self._setup_interpreter_tab()
        
    def _setup_parse_tab(self):
        """设置解析标签页"""
        self.parse_text = tk.Text(
            self.parse_frame,
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY,
            insertbackground=Theme.FG_PRIMARY,
            selectbackground=Theme.SELECTION,
            font=("Consolas", 10),
            wrap="word"
        )
        self.parse_text.pack(fill="both", expand=True, padx=5, pady=5)
        
    def _setup_properties_tab(self):
        """设置属性标签页"""
        self.properties_text = tk.Text(
            self.properties_frame,
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY,
            insertbackground=Theme.FG_PRIMARY,
            selectbackground=Theme.SELECTION,
            font=("Consolas", 10),
            wrap="word"
        )
        self.properties_text.pack(fill="both", expand=True, padx=5, pady=5)
        
    def _setup_interpreter_tab(self):
        """设置数据解释器标签页"""
        self.interpreter_text = tk.Text(
            self.interpreter_frame,
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY,
            insertbackground=Theme.FG_PRIMARY,
            selectbackground=Theme.SELECTION,
            font=("Consolas", 10),
            wrap="word"
        )
        self.interpreter_text.pack(fill="both", expand=True, padx=5, pady=5)
        
    def update_parse(self, text: str):
        """更新解析内容"""
        self.parse_text.delete(1.0, "end")
        self.parse_text.insert(1.0, text)
        
    def update_properties(self, analyzer: HexAnalyzer):
        """更新属性信息"""
        self.properties_text.delete(1.0, "end")
        
        # 计算哈希值
        import hashlib
        
        # 对于大文件，只计算前1MB的哈希
        hash_data = analyzer.data[:1024*1024] if analyzer.filesize > 1024*1024 else analyzer.data
        
        md5_hash = hashlib.md5(hash_data).hexdigest().upper()
        sha1_hash = hashlib.sha1(hash_data).hexdigest().upper()
        sha256_hash = hashlib.sha256(hash_data).hexdigest().upper()
        
        # 如果是大文件，添加提示
        hash_note = " (前1MB)" if analyzer.filesize > 1024*1024 else ""
        
        info = f"""文件信息
========
路径: {analyzer.filepath}
大小: {analyzer.filesize:,} 字节
格式: {analyzer.format.value}

哈希值{hash_note}
======
MD5:    {md5_hash}
SHA1:   {sha1_hash}
SHA256: {sha256_hash}

数据统计
========
熵值: {analyzer.calculate_entropy():.4f} / 8.0
"""
        self.properties_text.insert(1.0, info)
        
    def update_interpreter(self, data: bytes, offset: int):
        """更新数据解释"""
        self.interpreter_text.delete(1.0, "end")
        
        if not data:
            return
            
        # 这里简化实现，实际应该调用hex_pro中的解释器
        text = f"偏移: 0x{offset:04X}\n"
        text += f"长度: {len(data)} 字节\n\n"
        text += f"Hex: {data.hex().upper()}\n"
        
        if len(data) >= 1:
            text += f"\nuint8: {data[0]}\n"
        if len(data) >= 2:
            text += f"uint16 BE: {int.from_bytes(data[:2], 'big')}\n"
            text += f"uint16 LE: {int.from_bytes(data[:2], 'little')}\n"
        if len(data) >= 4:
            text += f"uint32 BE: {int.from_bytes(data[:4], 'big')}\n"
            text += f"uint32 LE: {int.from_bytes(data[:4], 'little')}\n"
            
        # ASCII
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        text += f"\nASCII: {ascii_str}\n"
        
        self.interpreter_text.insert(1.0, text)


class HexAnalyzerGUI:
    """主窗口类"""
    
    def __init__(self):
        # 创建主窗口
        if HAS_DND:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()
            
        self.root.title("十六进制分析器")
        self.root.geometry("1200x800")
        self.root.configure(bg=Theme.BG_PRIMARY)
        
        # 设置图标（如果存在）
        if os.path.exists("icon.ico"):
            self.root.iconbitmap("icon.ico")
            
        self.analyzer = None
        self.current_file = None
        
        self._setup_ui()
        self._setup_menu()
        self._setup_bindings()
        
        # 拖放支持
        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self._on_drop)
            
    def _setup_ui(self):
        """设置UI布局"""
        # 工具栏
        self.toolbar = tk.Frame(self.root, bg=Theme.BG_TERTIARY, height=40)
        self.toolbar.pack(fill="x", padx=1, pady=(1, 0))
        
        # 打开按钮
        self.open_btn = tk.Button(
            self.toolbar,
            text="打开",
            command=self.open_file,
            bg=Theme.BG_SECONDARY,
            fg=Theme.FG_PRIMARY,
            activebackground=Theme.BG_HOVER,
            relief="flat",
            padx=10
        )
        self.open_btn.pack(side="left", padx=5, pady=5)
        
        # 搜索框
        tk.Label(
            self.toolbar,
            text="搜索:",
            bg=Theme.BG_TERTIARY,
            fg=Theme.FG_SECONDARY
        ).pack(side="left", padx=(20, 5))
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            self.toolbar,
            textvariable=self.search_var,
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY,
            insertbackground=Theme.FG_PRIMARY,
            width=30
        )
        self.search_entry.pack(side="left", padx=5)
        
        self.search_btn = tk.Button(
            self.toolbar,
            text="查找",
            command=self.search,
            bg=Theme.BG_SECONDARY,
            fg=Theme.FG_PRIMARY,
            activebackground=Theme.BG_HOVER,
            relief="flat",
            padx=10
        )
        self.search_btn.pack(side="left", padx=5)
        
        # 主内容区域
        self.paned_main = ttk.PanedWindow(self.root, orient="horizontal")
        self.paned_main.pack(fill="both", expand=True, padx=1, pady=1)
        
        # 左侧面板
        self.left_frame = tk.Frame(self.paned_main, bg=Theme.BG_SECONDARY)
        self.paned_main.add(self.left_frame, weight=1)
        
        # 文件信息
        self.info_frame = tk.LabelFrame(
            self.left_frame,
            text="文件信息",
            bg=Theme.BG_SECONDARY,
            fg=Theme.FG_PRIMARY,
            font=("", 9, "bold")
        )
        self.info_frame.pack(fill="x", padx=5, pady=5)
        
        self.info_label = tk.Label(
            self.info_frame,
            text="未加载文件",
            bg=Theme.BG_SECONDARY,
            fg=Theme.FG_SECONDARY,
            justify="left"
        )
        self.info_label.pack(padx=5, pady=5)
        
        # 结构树
        self.tree_frame = tk.LabelFrame(
            self.left_frame,
            text="结构",
            bg=Theme.BG_SECONDARY,
            fg=Theme.FG_PRIMARY,
            font=("", 9, "bold")
        )
        self.tree_frame.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        self.structure_tree = StructureTree(self.tree_frame)
        tree_scroll = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.structure_tree.yview)
        self.structure_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.structure_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        
        # 右侧面板
        self.right_paned = ttk.PanedWindow(self.paned_main, orient="vertical")
        self.paned_main.add(self.right_paned, weight=3)
        
        # 十六进制视图
        self.hex_frame = tk.LabelFrame(
            self.right_paned,
            text="十六进制视图",
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY,
            font=("", 9, "bold")
        )
        self.right_paned.add(self.hex_frame, weight=2)
        
        self.hex_view = HexView(self.hex_frame)
        self.hex_view.pack(fill="both", expand=True, padx=1, pady=1)
        
        # 详细信息面板
        self.detail_panel = DetailPanel(self.right_paned)
        self.right_paned.add(self.detail_panel, weight=1)
        
        # 状态栏
        self.status_bar = tk.Label(
            self.root,
            text="就绪",
            bg=Theme.BG_TERTIARY,
            fg=Theme.FG_SECONDARY,
            anchor="w",
            padx=10
        )
        self.status_bar.pack(fill="x", side="bottom")
        
    def _setup_menu(self):
        """设置菜单栏"""
        self.menubar = tk.Menu(self.root, bg=Theme.BG_SECONDARY, fg=Theme.FG_PRIMARY)
        self.root.config(menu=self.menubar)
        
        # 文件菜单
        file_menu = tk.Menu(self.menubar, tearoff=0, bg=Theme.BG_SECONDARY, fg=Theme.FG_PRIMARY)
        self.menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="打开...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        
        # 编辑菜单
        edit_menu = tk.Menu(self.menubar, tearoff=0, bg=Theme.BG_SECONDARY, fg=Theme.FG_PRIMARY)
        self.menubar.add_cascade(label="编辑", menu=edit_menu)
        edit_menu.add_command(label="复制", accelerator="Ctrl+C")
        edit_menu.add_command(label="查找...", command=self.show_search_dialog, accelerator="Ctrl+F")
        edit_menu.add_command(label="跳转...", command=self.show_goto_dialog, accelerator="Ctrl+G")
        
        # 视图菜单
        view_menu = tk.Menu(self.menubar, tearoff=0, bg=Theme.BG_SECONDARY, fg=Theme.FG_PRIMARY)
        self.menubar.add_cascade(label="视图", menu=view_menu)
        view_menu.add_command(label="刷新", command=self.refresh_view, accelerator="F5")
        
        # 工具菜单
        tools_menu = tk.Menu(self.menubar, tearoff=0, bg=Theme.BG_SECONDARY, fg=Theme.FG_PRIMARY)
        self.menubar.add_cascade(label="工具", menu=tools_menu)
        tools_menu.add_command(label="解析TLV", command=self.parse_tlv)
        tools_menu.add_command(label="数据解释器", command=self.show_interpreter)
        
    def _setup_bindings(self):
        """设置快捷键绑定"""
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-f>", lambda e: self.show_search_dialog())
        self.root.bind("<Control-g>", lambda e: self.show_goto_dialog())
        self.root.bind("<F5>", lambda e: self.refresh_view())
        
        # 十六进制视图选择变化
        self.hex_view.bind("<<SelectionChanged>>", self._on_selection_changed)
        
        # 结构树点击
        self.structure_tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        
    def _on_drop(self, event):
        """处理文件拖放"""
        files = self.root.tk.splitlist(event.data)
        if files:
            self.load_file(files[0])
            
    def open_file(self):
        """打开文件对话框"""
        filename = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[("所有文件", "*.*")]
        )
        if filename:
            self.load_file(filename)
            
    def load_file(self, filepath: str):
        """加载文件"""
        try:
            # 更新状态
            self.status_bar.config(text=f"正在加载: {filepath}")
            self.root.update()
            
            # 创建分析器
            self.analyzer = HexAnalyzer(filepath)
            self.current_file = filepath
            
            # 更新UI
            self.hex_view.set_analyzer(self.analyzer)
            self._update_file_info()
            
            # 调试信息
            print(f"文件格式检测: {self.analyzer.format.value}")
            print(f"文件大小: {self.analyzer.filesize} 字节")
            
            self._parse_structure()
            
            # 更新详细面板
            self.detail_panel.update_properties(self.analyzer)
            
            # 更新状态
            self.status_bar.config(text=f"已加载: {os.path.basename(filepath)} | 大小: {self.analyzer.filesize:,} 字节 | 格式: {self.analyzer.format.value}")
            
        except Exception as e:
            messagebox.showerror("错误", f"无法加载文件:\n{str(e)}")
            self.status_bar.config(text="加载失败")
            
    def _update_file_info(self):
        """更新文件信息显示"""
        if not self.analyzer:
            return
            
        info_text = f"""文件: {os.path.basename(self.analyzer.filepath)}
大小: {self.analyzer.filesize:,} 字节
格式: {self.analyzer.format.value}"""
        
        self.info_label.config(text=info_text)
        
    def _parse_structure(self):
        """解析并显示结构"""
        if not self.analyzer:
            return
            
        # 清空树
        for item in self.structure_tree.get_children():
            self.structure_tree.delete(item)
            
        try:
            # 根据格式解析
            if self.analyzer.format.value in ["TLV结构", "护照数据组", "JPEG2000/JP2图像"]:
                # 增加解析深度到20层
                fields = self.analyzer.analyze_tlv(max_depth=20)
                
                # 调试信息
                print(f"TLV解析完成，找到 {len(fields)} 个顶层字段")
                self._count_fields(fields)
                
                self.structure_tree.load_tlv_fields(fields)
                
                # 递归展开所有层级
                self._expand_all(self.structure_tree)
        except Exception as e:
            import traceback
            error_msg = f"结构解析错误: {e}\n{traceback.format_exc()}"
            print(error_msg)
            # 在状态栏显示错误
            self.status_bar.config(text=f"结构解析错误: {e}")
            
    def _count_fields(self, fields: List[TLVField], level: int = 0):
        """统计字段数量（用于调试）"""
        for field in fields:
            print(f"{'  ' * level}Tag: {field.tag_bytes.hex().upper()} ({field.tag_description}) - {len(field.children)} 子节点")
            if field.children:
                self._count_fields(field.children, level + 1)
                
    def _expand_all(self, tree, item=''):
        """递归展开所有树节点"""
        children = tree.get_children(item)
        for child in children:
            tree.item(child, open=True)
            self._expand_all(tree, child)
            
    def _on_selection_changed(self, event):
        """处理选择变化"""
        selection = self.hex_view.get_selection()
        if selection and self.analyzer:
            start, end = selection
            data = self.analyzer.data[start:end]
            self.detail_panel.update_interpreter(data, start)
            
    def _on_tree_select(self, event):
        """处理树节点选择"""
        selection = self.structure_tree.selection()
        if selection:
            item = selection[0]
            values = self.structure_tree.item(item, "values")
            if values and len(values) > 1:
                # 获取偏移量
                offset_str = values[1]  # "0x1234"
                try:
                    offset = int(offset_str, 16)
                    length = int(values[2])
                    self.hex_view.highlight_range(offset, offset + length)
                except:
                    pass
                    
    def search(self):
        """执行搜索"""
        pattern = self.search_var.get()
        if not pattern or not self.analyzer:
            return
            
        # 简单实现：只搜索十六进制
        try:
            if all(c in '0123456789abcdefABCDEF ' for c in pattern):
                # 十六进制搜索
                hex_bytes = bytes.fromhex(pattern.replace(' ', ''))
                positions = self.analyzer.find_patterns(hex_bytes)
                
                if positions:
                    # 高亮第一个结果
                    self.hex_view.search_results = [(pos, pos + len(hex_bytes)) for pos in positions]
                    self.hex_view.goto_offset(positions[0])
                    self.hex_view.refresh()
                    self.status_bar.config(text=f"找到 {len(positions)} 个匹配")
                else:
                    self.status_bar.config(text="未找到匹配")
            else:
                # 文本搜索
                text_bytes = pattern.encode('utf-8')
                positions = self.analyzer.find_patterns(text_bytes)
                
                if positions:
                    self.hex_view.search_results = [(pos, pos + len(text_bytes)) for pos in positions]
                    self.hex_view.goto_offset(positions[0])
                    self.hex_view.refresh()
                    self.status_bar.config(text=f"找到 {len(positions)} 个匹配")
                else:
                    self.status_bar.config(text="未找到匹配")
                    
        except Exception as e:
            self.status_bar.config(text=f"搜索错误: {e}")
            
    def show_search_dialog(self):
        """显示搜索对话框"""
        # 简单实现：聚焦到搜索框
        self.search_entry.focus_set()
        
    def show_goto_dialog(self):
        """显示跳转对话框"""
        if not self.analyzer:
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("跳转到偏移")
        dialog.geometry("300x100")
        dialog.configure(bg=Theme.BG_SECONDARY)
        
        tk.Label(
            dialog,
            text="偏移量:",
            bg=Theme.BG_SECONDARY,
            fg=Theme.FG_PRIMARY
        ).pack(pady=10)
        
        offset_var = tk.StringVar()
        entry = tk.Entry(
            dialog,
            textvariable=offset_var,
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY
        )
        entry.pack(pady=5)
        entry.focus_set()
        
        def goto():
            try:
                offset_str = offset_var.get()
                if offset_str.startswith("0x"):
                    offset = int(offset_str, 16)
                else:
                    offset = int(offset_str)
                self.hex_view.goto_offset(offset)
                dialog.destroy()
            except:
                pass
                
        tk.Button(
            dialog,
            text="跳转",
            command=goto,
            bg=Theme.BG_PRIMARY,
            fg=Theme.FG_PRIMARY
        ).pack(pady=10)
        
        entry.bind("<Return>", lambda e: goto())
        
    def refresh_view(self):
        """刷新视图"""
        if self.analyzer:
            self.hex_view.refresh()
            self._parse_structure()
            
    def parse_tlv(self):
        """解析TLV结构"""
        if self.analyzer:
            try:
                fields = self.analyzer.analyze_tlv()
                # 更新解析标签页
                tlv_text = self._format_tlv_text(fields)
                self.detail_panel.update_parse(tlv_text)
                self.detail_panel.select(0)  # 切换到解析标签页
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                messagebox.showerror("错误", f"TLV解析失败:\n{str(e)}\n\n详细信息:\n{error_details}")
                
    def _format_tlv_text(self, fields: List[TLVField], indent: int = 0) -> str:
        """格式化TLV文本"""
        lines = []
        for field in fields:
            prefix = "  " * indent
            tag_hex = field.tag_bytes.hex().upper()
            
            line = f"{prefix}{tag_hex} {field.tag_description} @ 0x{field.offset:04X} ({field.length} bytes)"
            
            if field.parsed_value:
                line += f" = {field.parsed_value}"
            elif len(field.value) <= 16 and not field.children:
                line += f" = {field.value.hex().upper()}"
                
            lines.append(line)
            
            if field.children:
                lines.append(self._format_tlv_text(field.children, indent + 1))
                
        return "\n".join(lines)
        
    def show_interpreter(self):
        """显示数据解释器"""
        self.detail_panel.select(2)  # 切换到解释器标签页
        
    def run(self):
        """运行应用"""
        # 如果有命令行参数，尝试加载文件
        if len(sys.argv) > 1:
            self.root.after(100, lambda: self.load_file(sys.argv[1]))
            
        self.root.mainloop()


def main():
    """主函数"""
    app = HexAnalyzerGUI()
    app.run()


if __name__ == "__main__":
    main()