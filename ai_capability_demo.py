#!/usr/bin/env python3
"""
AI Capability Demonstration
展示 Claude Opus 4 的编程能力
"""

import numpy as np
import time
from typing import List, Tuple, Dict, Optional
from collections import defaultdict, deque
import heapq

class AICapabilityDemo:
    """展示各种高级算法和数据结构的实现"""
    
    def __init__(self):
        self.demo_name = "Claude Opus 4 能力展示"
        
    def dynamic_programming_demo(self, items: List[Tuple[int, int]], capacity: int) -> int:
        """
        动态规划示例：0-1背包问题
        items: [(weight, value), ...]
        capacity: 背包容量
        """
        n = len(items)
        dp = [[0] * (capacity + 1) for _ in range(n + 1)]
        
        for i in range(1, n + 1):
            weight, value = items[i-1]
            for w in range(capacity + 1):
                if weight <= w:
                    dp[i][w] = max(dp[i-1][w], dp[i-1][w-weight] + value)
                else:
                    dp[i][w] = dp[i-1][w]
        
        return dp[n][capacity]
    
    def graph_algorithm_demo(self, graph: Dict[int, List[Tuple[int, int]]], start: int) -> Dict[int, int]:
        """
        图算法示例：Dijkstra最短路径算法
        graph: {node: [(neighbor, weight), ...]}
        """
        distances = defaultdict(lambda: float('inf'))
        distances[start] = 0
        pq = [(0, start)]
        visited = set()
        
        while pq:
            curr_dist, curr_node = heapq.heappop(pq)
            
            if curr_node in visited:
                continue
                
            visited.add(curr_node)
            
            for neighbor, weight in graph.get(curr_node, []):
                distance = curr_dist + weight
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    heapq.heappush(pq, (distance, neighbor))
        
        return dict(distances)
    
    def machine_learning_demo(self, X: np.ndarray, y: np.ndarray, learning_rate: float = 0.01, epochs: int = 1000) -> np.ndarray:
        """
        机器学习示例：梯度下降实现线性回归
        """
        m, n = X.shape
        # 添加偏置项
        X_b = np.c_[np.ones((m, 1)), X]
        theta = np.random.randn(n + 1, 1)
        
        for epoch in range(epochs):
            gradients = 2/m * X_b.T.dot(X_b.dot(theta) - y)
            theta = theta - learning_rate * gradients
            
            if epoch % 100 == 0:
                cost = np.mean((X_b.dot(theta) - y) ** 2)
                print(f"Epoch {epoch}, Cost: {cost:.4f}")
        
        return theta
    
    def advanced_data_structure_demo(self):
        """
        高级数据结构示例：实现一个LRU缓存
        """
        class LRUCache:
            def __init__(self, capacity: int):
                self.capacity = capacity
                self.cache = {}
                self.order = deque()
            
            def get(self, key: int) -> int:
                if key not in self.cache:
                    return -1
                self.order.remove(key)
                self.order.append(key)
                return self.cache[key]
            
            def put(self, key: int, value: int) -> None:
                if key in self.cache:
                    self.order.remove(key)
                elif len(self.cache) >= self.capacity:
                    oldest = self.order.popleft()
                    del self.cache[oldest]
                
                self.cache[key] = value
                self.order.append(key)
        
        return LRUCache
    
    def concurrent_programming_demo(self):
        """
        并发编程示例：生产者-消费者模式
        """
        import threading
        import queue
        
        def producer(q: queue.Queue, items: List[str]):
            for item in items:
                time.sleep(0.1)
                q.put(item)
                print(f"生产: {item}")
            q.put(None)  # 结束信号
        
        def consumer(q: queue.Queue, name: str):
            while True:
                item = q.get()
                if item is None:
                    q.put(None)  # 传递结束信号给其他消费者
                    break
                time.sleep(0.2)
                print(f"{name} 消费: {item}")
                q.task_done()
        
        return producer, consumer
    
    def algorithm_complexity_analysis(self):
        """
        算法复杂度分析示例
        """
        analysis = {
            "排序算法": {
                "快速排序": {"时间复杂度": "O(n log n) 平均", "空间复杂度": "O(log n)"},
                "归并排序": {"时间复杂度": "O(n log n)", "空间复杂度": "O(n)"},
                "堆排序": {"时间复杂度": "O(n log n)", "空间复杂度": "O(1)"}
            },
            "搜索算法": {
                "二分查找": {"时间复杂度": "O(log n)", "空间复杂度": "O(1)"},
                "深度优先搜索": {"时间复杂度": "O(V + E)", "空间复杂度": "O(V)"},
                "广度优先搜索": {"时间复杂度": "O(V + E)", "空间复杂度": "O(V)"}
            }
        }
        return analysis

def main():
    """主函数：运行所有演示"""
    print("=== Claude Opus 4 能力展示 ===\n")
    
    demo = AICapabilityDemo()
    
    # 1. 动态规划演示
    print("1. 动态规划 - 0-1背包问题:")
    items = [(2, 1), (1, 2), (3, 4), (2, 2)]
    capacity = 5
    max_value = demo.dynamic_programming_demo(items, capacity)
    print(f"   物品: {items}")
    print(f"   背包容量: {capacity}")
    print(f"   最大价值: {max_value}\n")
    
    # 2. 图算法演示
    print("2. 图算法 - Dijkstra最短路径:")
    graph = {
        0: [(1, 4), (2, 2)],
        1: [(2, 1), (3, 5)],
        2: [(3, 8), (4, 10)],
        3: [(4, 2)],
        4: []
    }
    distances = demo.graph_algorithm_demo(graph, 0)
    print(f"   从节点0到各节点的最短距离: {distances}\n")
    
    # 3. 机器学习演示
    print("3. 机器学习 - 线性回归:")
    np.random.seed(42)
    X = 2 * np.random.rand(100, 1)
    y = 4 + 3 * X + np.random.randn(100, 1)
    print("   训练线性回归模型...")
    theta = demo.machine_learning_demo(X, y, learning_rate=0.1, epochs=300)
    print(f"   学习到的参数: θ₀={theta[0][0]:.2f}, θ₁={theta[1][0]:.2f}")
    print(f"   (真实参数: θ₀=4, θ₁=3)\n")
    
    # 4. 数据结构演示
    print("4. 高级数据结构 - LRU缓存:")
    LRUCache = demo.advanced_data_structure_demo()
    cache = LRUCache(3)
    operations = [
        ("put", 1, 1), ("put", 2, 2), ("get", 1), 
        ("put", 3, 3), ("put", 4, 4), ("get", 2)
    ]
    print("   执行操作序列:")
    for op in operations:
        if op[0] == "put":
            cache.put(op[1], op[2])
            print(f"   {op[0]}({op[1]}, {op[2]})")
        else:
            result = cache.get(op[1])
            print(f"   {op[0]}({op[1]}) -> {result}")
    
    # 5. 算法复杂度分析
    print("\n5. 算法复杂度分析:")
    analysis = demo.algorithm_complexity_analysis()
    for category, algorithms in analysis.items():
        print(f"   {category}:")
        for algo, complexity in algorithms.items():
            print(f"     - {algo}: {complexity}")
    
    print("\n=== 演示完成 ===")
    print("\n这个演示展示了 Claude Opus 4 在以下方面的能力：")
    print("• 复杂算法实现（动态规划、图算法）")
    print("• 机器学习算法（梯度下降）")
    print("• 高级数据结构设计（LRU缓存）")
    print("• 并发编程模式")
    print("• 算法分析和优化")
    print("\n我可以帮助您解决各种复杂的编程问题！")

if __name__ == "__main__":
    main()