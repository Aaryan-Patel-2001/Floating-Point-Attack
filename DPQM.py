from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

# SYSTEM: Differentially Private Query Management (DPQM) 
# Stores alpha-numeric datasets and provides differentially private query results
# Query formats supported: 
#   - Total records count
#   - Count of all records with a certain pattern and a certain value

@dataclass
class QueryResult:
    count: Optional[int]
    confidence: float
    noisy_values: List[float]  # Store raw noisy values for analysis

class VulnerablePrivateNameDatabase:
    def __init__(self, names: List[str], epsilon: float = 0.1, max_budget: float = 5.0):
        self.names = [name.lower() for name in names]
        self.epsilon64bit = np.float64(epsilon)
        self.total_budget_spent = 0
        self.max_budget = max_budget
    
    def double_precision_laplace_noise(self, scale: float) -> float:
        """Generates Laplace noise with 64 bit double precision"""
        u1 = np.float64(np.random.random())
        u2 = np.float64(np.random.random())

        if u1 <= 0.5:
            noise = np.float64(scale * np.log(np.float64(2.0 * u2)))
        else:
            noise =  np.float64(-scale * np.log(np.float64(2.0 * (1.0 - u2))))

        return noise
    
    def vulnerable_count_64bit(self, pattern: str) -> Optional[np.float16]:
        """Returns noisy count with float 64 bit double precision"""
        if self.total_budget_spent >= self.max_budget:
            return None

        if pattern == "_":
            true_count = np.float64(len(self.names))
        else:
            true_count = np.float64(
                sum(
                    1
                    for name in self.names
                    if len(name) == len(pattern)
                    and all(p == "_" or p == c for p, c in zip(pattern, name))
                )
            )

        # Vulnerable Laplace noise
        scale = np.float64(1.0 / self.epsilon64bit)
        noise = self.double_precision_laplace_noise(scale)

        self.total_budget_spent +=  self.epsilon64bit
        return np.float64(true_count + noise)
    
    def prefix_query_64bit(self, pattern: str) -> Optional[np.float16]:
        """Query for count of all records with a certain prefix"""
        if self.total_budget_spent >= self.max_budget:
            return None

        true_count = np.float64(
            sum(1 for name in self.names if name.startswith(pattern))
        )

        scale = np.float64(1.0 / self.epsilon64bit)
        noise = self.double_precision_laplace_noise(scale)

        self.total_budget_spent += self.epsilon64bit

        return np.float64(true_count + noise)
    
    def size(self) -> int: 
        return len(self.names)
    
    # def vulnerable_laplace_noise(self, scale: float) -> np.float16:
    #     """Generates Laplace noise with float16 vulnerability"""
    #     u1 = np.float16(np.random.random())
    #     u2 = np.float16(np.random.random())

    #     if u1 <= 0.5:
    #         noise = np.float16(scale * np.log(np.float16(2.0 * u2)))
    #     else:
    #         noise = np.float16(-scale * np.log(np.float16(2.0 * (1.0 - u2))))

    #     return noise
        # def prefix_query(self, pattern: str) -> Optional[np.float16]:
        # """Query for count of all records with a certain prefix"""
        # if self.total_budget_spent >= self.max_budget:
        #     return None

        # true_count = np.float16(
        #     sum(1 for name in self.names if name.startswith(pattern))
        # )

        # scale = np.float16(1.0 / self.epsilon)
        # noise = self.vulnerable_laplace_noise(scale)

        # self.total_budget_spent +=  self.epsilon

        # return np.float16(true_count + noise)

        #     def vulnerable_count(self, pattern: str) -> Optional[np.float16]:
        # """Returns noisy count with float16 vulnerability"""
        # if self.total_budget_spent >= self.max_budget:
        #     return None

        # if pattern == "_":
        #     true_count = np.float16(len(self.names))
        # else:
        #     true_count = np.float16(
        #         sum(
        #             1
        #             for name in self.names
        #             if len(name) == len(pattern)
        #             and all(p == "_" or p == c for p, c in zip(pattern, name))
        #         )
        #     )

        # # Vulnerable Laplace noise
        # scale = np.float16(1.0 / self.epsilon)
        # noise = self.vulnerable_laplace_noise(scale)

        # # print("epsilon is: ", self.epsilon)
        # # print("budget spent is: ", self.total_budget_spent)
        # self.total_budget_spent += self.epsilon
        # return np.float16(true_count + noise)