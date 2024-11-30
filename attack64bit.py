from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
from DPQM import VulnerablePrivateNameDatabase, QueryResult

class Queries2: 
   def __init__(self, db: VulnerablePrivateNameDatabase):
        self.db = db
        self.alphabet = "abcdefghijklmnopqrstuvwxyz"
        self.epsilon = db.epsilon64bit

   def analyze_with_known_scale(self, noisy_values, dtype=np.float64):
        """
        Analyze noisy values using knowledge of the noise scale to find likely original value

        Args:
            noisy_values: Array of noisy measurements
            noise_scale: The scale factor used for noise (relative to true value)
        """
        # convert noisy_values to float64
        noise_scale = 1/self.epsilon
        if dtype != np.float64:
            noisy_values = np.array(noisy_values, dtype=np.float64)

        # First, get a rough estimate of magnitude
        median_value = np.median(noisy_values)
        estimated_magnitude = abs(median_value)

        # Expected noise magnitude
        expected_noise = estimated_magnitude * noise_scale

        # The spacing between representable floating point numbers at this magnitude
        # if dtype != np.float64:
        #     machine_epsilon_at_magnitude = estimated_magnitude * np.finfo(dtype).eps
        # else:
        #     machine_epsilon_at_magnitude = estimated_magnitude * np.finfo(float).eps

        machine_epsilon_at_magnitude = estimated_magnitude * np.finfo(float).eps
        # Compute a reasonable bin width based on noise scale and float precision
        bin_width = max(machine_epsilon_at_magnitude, expected_noise / 100)

        # Center and normalize the data
        centered_values = noisy_values - median_value

        # Round to likely floating point boundaries
        rounded = np.round(centered_values / bin_width) * bin_width

        # Count frequencies with weights based on distance from expected noise distribution
        weights = {}
        for value in rounded:
            # Weight based on how likely this deviation is given the noise scale
            deviation = abs(value) / expected_noise
            # Use Laplace distribution properties since we used Laplace noise
            weight = np.exp(-deviation)

            if value not in weights:
                weights[value] = 0
            weights[value] += weight

        # Sort by weighted frequency
        sorted_values = sorted(weights.items(), key=lambda x: x[1], reverse=True)

        # Return recovered values with their weights, adjusted back to original scale
        recovered_values = [(v + median_value, w) for v, w in sorted_values]

        return recovered_values

   def analyze_noisy_samples(
        self, values: List[float], base_tolerance: float = 0.1
    ) -> Tuple[Optional[int], float]:
        """
        Analyze noisy samples to estimate true count and confidence
        Returns (estimated_count, confidence)
        """
        # print("Analyze noisy sample called", values)
        if not values:
            return None, 0.0
        
        # Analyze noisy values
        recovered_values = self.analyze_with_known_scale(values)
        if not recovered_values:
            return None, 0.0
        
        # print(f"Recovered values: {recovered_values}\n")
        count = max(0, round(recovered_values[0][0]))
        
        return count, 1.0
   
   def query_with_confidence(self, pattern: str, samples: int = 25) -> QueryResult:
        """Make multiple queries and analyze results with improved clustering. Brute force method."""
        noisy_values = []
        for _ in range(samples):
            result = self.db.vulnerable_count_64bit(pattern)
            if result is None:  # Budget exhausted
                if noisy_values:  # Use whatever samples we got
                    break
                return QueryResult(None, 0.0, [])
            noisy_values.append(float(result))

        if not noisy_values:
            return QueryResult(None, 0.0, [])

        # Enhanced analysis of noisy values
        estimated_count, confidence = self.analyze_noisy_samples(noisy_values)

        if estimated_count is None:
            return QueryResult(0, 0.0, noisy_values)

        return QueryResult(estimated_count, confidence, noisy_values)
   
   def get_raw_first_letter_count(self): 
       result = {}
       for alphabet in self.alphabet: 
           try: 
            result[alphabet] = max(0, round(self.db.prefix_query_64bit(alphabet)))
           except:
            result[alphabet] = 0
       return result

class ConstrainedTreeAttacker64bit:
    def __init__(self, db: VulnerablePrivateNameDatabase):
        self.db = db
        self.alphabet = "abcdefghijklmnopqrstuvwxyz"
        self.total_count = db.size()
        self.length_distribution = {}
        self.qm = Queries2(db)

    def determine_length_distribution(self) -> bool:
        """ Determine length distribution """
        remaining_count = self.total_count
        for length in range(2, 10):
            result = self.qm.query_with_confidence("_" * length, samples=7)
            if result.count is None:
                break

            if result.count > 0 and result.confidence > 0.3:  # Lowered threshold
                self.length_distribution[length] = min(result.count, remaining_count)
                remaining_count -= self.length_distribution[length]
                # print( f"Length {length}: {result.count} (confidence: {result.confidence:.2f})")

            if remaining_count <= 0:
                break

        if (remaining_count > 0):
            return False
            # print("Failed to determine all length distribution")

        print(f"Length distribution: {self.length_distribution}\n")
        print(f"Privacy cost spent after length distribution:{self.db.total_budget_spent}\n")

        return len(self.length_distribution) > 0
    
    def get_first_letters (self) -> Dict[str, float]:
        """Get the first letter of the name"""
        first_letter_count = self.qm.get_raw_first_letter_count()

        total_sum = 0.0 
        i = 1
        keystodelete = []
        for key, value in first_letter_count.items():
            total_sum += value
            if value == 0: 
                keystodelete.append(key)
        for key in keystodelete:
            del first_letter_count[key]
        # print(f"Raw First letter count: {first_letter_count}\n")
        # print(f"Total sum: {total_sum}\n")

        keystodelete = []
        while(total_sum < self.total_count): 
            # print(f"entered {i}th iteration of the while loop\n")
            total_sum = 0.0
            first_letter_count = self.qm.get_raw_first_letter_count()
            for key, value in first_letter_count.items():
                total_sum += value
                if value == 0: 
                    keystodelete.append(key)
            for key in keystodelete: 
                del first_letter_count[key]
            i += 1

        resconstructed_first_letters = {}
        confidence = 0.0
        for length, length_count in self.length_distribution.items():
            remaining_count = length_count
            prefix_tree = {}
            for key, value in first_letter_count.items():
                if remaining_count <= 0:
                    break

                pattern = f"{key}{'_' * (length-1)}"
                result = self.qm.query_with_confidence(pattern)

                if result.count is None:
                    break

                if result.count > 0:  # Lowered threshold
                    prefix_tree[key] = result.count
                    confidence += result.confidence
                    remaining_count -= result.count

            resconstructed_first_letters[length] = prefix_tree   

        print(f"First letter distribution: {resconstructed_first_letters}\n")
        print(f"Privacy cost spent after first letter distribution: {self.db.total_budget_spent}\n")
        values_found = self.total_count - max(0, remaining_count)
        return resconstructed_first_letters
    
    def reconstruct_names(self) -> Dict[str, float]:
        """Reconstruct names"""
        reconstructed_names = {}
        self.determine_length_distribution()
        first_letters = self.get_first_letters()
        for length, length_count in self.length_distribution.items():
            prefix_tree = first_letters[length]
            for prefix, count in list(prefix_tree.items()):
                current_prefixes = [(prefix, count)]
                while current_prefixes:
                    current_prefix, expected_count = current_prefixes.pop(0)
                    if len(current_prefix) == length:
                        reconstructed_names[current_prefix] = 1.0
                        continue
                    position_count = expected_count
                    for letter in self.alphabet:
                        if position_count <= 0:
                            break
                        new_prefix = current_prefix + letter
                        pattern = new_prefix + "_" * (length - len(new_prefix))
                        result = self.qm.query_with_confidence(pattern)
                        if result.count is None:
                            break
                        if result.count > 0 and result.confidence > 0.6:
                            current_prefixes.append((new_prefix, result.count))
                            position_count -= result.count
        return reconstructed_names


if __name__ == "__main__":
    names = ["aaryan", "alex", "elliot", "kassem", "Alice", "Bob", "Eve"]
    # Length distribution: {1:0, 2:0, 3:2, 4:1, 5:1, 6:3}
    db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=10000.0)
    attacker = ConstrainedTreeAttacker64bit(db)
    print("size of dataset: ", attacker.total_count)
    print(attacker.reconstruct_names())
    print("total budget spent:",  db.total_budget_spent)