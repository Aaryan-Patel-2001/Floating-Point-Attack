from typing import Dict
import numpy as np
from DPQM import VulnerablePrivateNameDatabase, QueryResult
from queries import Queries
from attack import ConstrainedTreeAttacker
from attack64bit import ConstrainedTreeAttacker64bit, Queries2
import matplotlib.pyplot as plt


def compare_first_letter_distributions(dict1: Dict[int, Dict[str, int]], dict2: Dict[int, Dict[str, int]]) -> float:
        total_first_letters = 0
        correct_first_letters = 0

        for length, letters_dict1 in dict1.items():
            if length in dict2:
                letters_dict2 = dict2[length]
                for letter, count1 in letters_dict1.items():
                    count2 = letters_dict2.get(letter, 0)
                    total_first_letters += count1
                    correct_first_letters += min(count1, count2)

        if total_first_letters == 0:
            return 0.0

        return (correct_first_letters / total_first_letters) * 100

def length_distribution_experiment(names, truedistribution, times=100): 
    """Experiment to test the success rate of determining the length distribution: using regular and adaptive sampling"""
    print("size of dataset: ", len(names))
    success_rate = 0.0 
    success_rate_adaptive = 0.0
    privacy_loss = 0.0
    privacy_loss_64bit = 0.0
    success_rate_64bit = 0.0
    for _ in range(times): 
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=10000.0)
        attacker = ConstrainedTreeAttacker(db)
        attacker.determine_length_distribution()
        if (attacker.length_distribution == truedistribution): 
            success_rate += 1.0
    print(f"success rate (without adpative sampling): {success_rate/times}")
    for _ in range(times): 
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=10000.0)
        attacker = ConstrainedTreeAttacker(db)
        attacker.adaptive_length_distribution()
        privacy_loss += db.total_budget_spent
        if (attacker.length_distribution == truedistribution): 
            success_rate_adaptive += 1.0
    print(f"success rate (with adpative sampling): {success_rate_adaptive/times}")
    print(f"Average privacy loss: {privacy_loss/times}")
    for _ in range(times):
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=10000.0)
        attacker = ConstrainedTreeAttacker64bit(db)
        attacker.adaptive_length_distribution()
        privacy_loss_64bit += db.total_budget_spent
        if (attacker.length_distribution == truedistribution): 
            success_rate_64bit += 1.0
    print(f"success rate (with adpative sampling and 64-bit precision): {success_rate_64bit/times}")
    print(f"Average privacy loss (64-bit precision): {privacy_loss_64bit/times}")


def first_letter_distribution_experiment(names, truedistribution, times=100): 
    """Experiment to test the success rate of determining the first letter distribution: using regular and adaptive sampling"""
    print("size of dataset: ", len(names))
    success_rate = 0.0 
    success_rate_adaptive = 0.0
    percentage_correct = 0.0
    percentage_correct_adaptive = 0.0
    success_rate_64bit = 0.0
    percentage_correct_64bit = 0.0
    for _ in range(times): 
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=2000.0)
        attacker = ConstrainedTreeAttacker(db)
        attacker.adaptive_length_distribution()
        letters1 = attacker.first_letter_ct()
        percentage_correct += compare_first_letter_distributions(letters1, truedistribution)
        if (letters1 == truedistribution): 
            success_rate += 1.0
    print(f"success rate : {(success_rate/times)*100}%")
    print(f"Percentage of correctly identified first letters: {(percentage_correct/times):.2f}%")
    for _ in range(times): 
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=2000.0)
        attacker = ConstrainedTreeAttacker(db)
        attacker.adaptive_length_distribution()
        letters2 = attacker.get_first_letters()
        percentage_correct_adaptive += compare_first_letter_distributions(letters2, truedistribution)
        if (letters2 == truedistribution): 
            success_rate_adaptive += 1.0
    print(f"Percentage of correctly identified first letters: {(percentage_correct_adaptive/times):.2f}%")
    print(f"success rate (Getting raw first-letter values first): {(success_rate_adaptive/times)*100}%")
    for _ in range(times):
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=2000.0)
        attacker = ConstrainedTreeAttacker64bit(db)
        attacker.adaptive_length_distribution()
        letters3 = attacker.get_first_letters()
        percentage_correct_64bit += compare_first_letter_distributions(letters3, truedistribution)
        if (letters3 == truedistribution): 
            success_rate_64bit += 1.0
    print(f"success rate (with 64-bit precision): {(success_rate_64bit/times)*100}%")
    print(f"Percentage of correctly identified first letters (64-bit precision): {(percentage_correct_64bit/times):.2f}%")


def query_experiment(names):
    sample = [10, 25, 100, 250, 500, 1000, 2500, 3500, 5000] 
    confidence16bit = []
    confidence64bit = []
    pattern = "b__eem"
    for i in [0, 100]: 
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=2000.0)
        query = Queries(db)
        query_result = query.query_with_confidence(pattern, samples=i)
        confidence16bit.append(query_result.confidence)
    for i in [0, 100]:
        db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=2000.0)
        query = Queries2(db)
        query_result = query.query_with_confidence(pattern, samples=i)
        confidence64bit.append(query_result.confidence)
        # Plot the data
    plt.figure(figsize=(10, 6))
    plt.plot([0, 100], confidence16bit, label='16-bit Precision', marker='o')
    plt.plot([0, 100], confidence64bit, label='64-bit Precision', marker='o')
    
    plt.xlabel('Sample Size')
    plt.ylabel('Confidence')
    plt.title('Confidence vs. Sample Size for 16-bit and 64-bit Precision')
    plt.legend()
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    names = ["aaryan", "alex", "elliot", "kassem", "Alice", "Bob", "Eve"]
    # Length distribution: {1:0, 2:0, 3:2, 4:1, 5:1, 6:3}
    db = VulnerablePrivateNameDatabase(names, epsilon=1.0, max_budget=2000.0)
    # test_database_properties_extraction(db)
    # length_distribution_experiment(names, {3:2, 4:1, 5:1, 6:3}, times=5000)
    # first_letter_distribution_experiment(names, {3:{'a':1, 'e':1}, 4:{'a':1}, 5:{'a':1}, 6:{'a':1, 'e':1, 'k':1}}, times=5000)
    query_experiment(names)
