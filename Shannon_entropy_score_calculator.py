import math

"""
Function to identify the average amount of uncertainty, surprise, or information content in a word.
Input: String - Word to calculate the entropy score of
Output: Float - Number of bits per character needed to represent its information
Low Entropy Scores: Data is highly predictable, repetitive, or dominated by one or a few common outcomes
High Entropy Scores: High randomness, uniform distribution, and maximum uncertainty. All potential states appear with roughly equal frequency
"""
def entropy_scorer(word: str) -> float:
    letter_to_amount_dictionary = {}
    amount_of_letters = len(word)

    """Find how many times each character appears in the word"""
    for character in word:
        letter_to_amount_dictionary[character] = letter_to_amount_dictionary.get(character, 0) + 1

    """
    Calculate score based on the following formula:
    H(X) = -SUM(p(x)log_2(x))
    Entropy of a word equals the negative sum of the probability of each character times the number of bits needed to reprent that character.
    """
    entropy_score = 0
    for letter in letter_to_amount_dictionary:
        probability = letter_to_amount_dictionary[letter] / amount_of_letters
        proportion_of_bit = probability * math.log2(probability)
        entropy_score += proportion_of_bit
    entropy_score *= -1

    return entropy_score

print(entropy_scorer("lot"))