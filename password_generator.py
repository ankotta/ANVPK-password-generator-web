# import modules
import secrets # for secure random choices
import string # for character groups


# SystemRandom uses the operating system's secure randomness,
# which is better for passwords than the regular random module.
secure_random = secrets.SystemRandom()


# The password policy requires at least 16 characters.
minimum_length = 16

# These symbols satisfy the special character requirement.
# Spaces, @ signs, double quotes, and commas are intentionally excluded.
symbols = list("!#$%&*?-_.:~")
banned_characters = {" ", "@", "\"", ","}


# These are small English-like sound pieces, not dictionary words.
# They make passwords easier to pronounce without using words.txt.
onsets = [
    "b", "br", "c", "ch", "cl", "cr", "d", "dr", "f", "fl", "fr",
    "g", "gl", "gr", "h", "j", "k", "l", "m", "n", "p", "pl", "pr",
    "r", "s", "sh", "sl", "sm", "sn", "sp", "st", "t", "tr",
    "v", "w", "z"
]

# Vowels form the middle of each fake syllable.
vowels = ["a", "e", "i", "o", "u", "ae", "ai", "ea", "ee", "oa", "oo"]

# Codas are optional endings for fake syllables.
codas = [
    "", "b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t",
    "ck", "ld", "mp", "nd", "ng", "nk", "nt", "rd", "sh", "sk", "st"
]


def make_syllable(length):

    # Create one readable fake syllable with the exact requested length.
    choices = [
        onset + vowel + coda
        for onset in onsets
        for vowel in vowels
        for coda in codas
        if len(onset + vowel + coda) == length
    ]

    return secure_random.choice(choices)


def choose_chunk_count(password_length):

    # Every password has 2 digits and one symbol between each fake-word chunk.
    # This finds a chunk count that can fit the exact requested length.
    for chunk_count in range(4, password_length):

        symbol_count = chunk_count - 1
        digit_count = 2
        total_letter_count = password_length - symbol_count - digit_count
        shortest_possible = chunk_count * 2
        longest_possible = chunk_count * 6

        if shortest_possible <= total_letter_count <= longest_possible:

            return chunk_count

    raise RuntimeError("Could not fit readable chunks into the requested length.")


def choose_chunk_lengths(password_length, chunk_count):

    # Choose exact fake-word lengths so letters + digits + symbols equal the input.
    symbol_count = chunk_count - 1
    digit_count = 2
    total_letter_count = password_length - symbol_count - digit_count
    chunk_lengths = [2] * chunk_count
    remaining_letters = total_letter_count - sum(chunk_lengths)

    while remaining_letters > 0:

        index = secure_random.randrange(chunk_count)

        if chunk_lengths[index] < 6:

            chunk_lengths[index] += 1
            remaining_letters -= 1

    secure_random.shuffle(chunk_lengths)

    return chunk_lengths


def make_fake_word(length):

    # One fake syllable keeps each chunk short and easier to remember.
    return make_syllable(length)


def has_required_character_types(password):

    # Check for at least 1 uppercase, lowercase, number, and special character.
    return (
        any(character in string.ascii_uppercase for character in password)
        and any(character in string.ascii_lowercase for character in password)
        and any(character in string.digits for character in password)
        and any(character in symbols for character in password)
    )


def choose_separator_symbols(count):

    # Use different separators when possible to avoid a visible repeated pattern.
    shuffled_symbols = symbols.copy()
    secure_random.shuffle(shuffled_symbols)

    while len(shuffled_symbols) < count:

        shuffled_symbols.append(secure_random.choice(symbols))

    return shuffled_symbols[:count]


def has_banned_characters(password):

    # The password policy does not allow spaces, @ signs, double quotes, or commas.
    return any(character in banned_characters for character in password)


def has_simple_repeating_pattern(password):

    # Reject obvious repeated chunks like "aaa", "abab", or "abcabc".
    lowered_password = password.lower()

    for chunk_size in range(1, 4):

        for index in range(len(lowered_password) - (chunk_size * 2) + 1):

            first_chunk = lowered_password[index:index + chunk_size]
            second_chunk = lowered_password[index + chunk_size:index + (chunk_size * 2)]

            if first_chunk == second_chunk:

                return True

    return False


def is_sequential(password, sequence):

    # Reject obvious 3-character sequences like "abc", "cba", "123", or "321".
    lowered_password = password.lower()

    for index in range(len(sequence) - 2):

        forward_sequence = sequence[index:index + 3]
        backward_sequence = forward_sequence[::-1]

        if forward_sequence in lowered_password or backward_sequence in lowered_password:

            return True

    return False


def password_meets_policy(password, requested_length):

    # Treat the password policy as a pass/fail rule set.
    return (
        len(password) == requested_length
        and len(password) >= minimum_length
        and has_required_character_types(password)
        and not has_banned_characters(password)
        and not has_simple_repeating_pattern(password)
        and not is_sequential(password, string.ascii_lowercase)
        and not is_sequential(password, string.digits)
    )


def make_memorable_password(requested_length):

    # Try multiple times because random chunks can accidentally make patterns.
    for _ in range(1000):

        chunk_count = choose_chunk_count(requested_length)
        chunk_lengths = choose_chunk_lengths(requested_length, chunk_count)
        chunks = [make_fake_word(length) for length in chunk_lengths]

        # Capitalize one chunk to guarantee an uppercase letter.
        uppercase_index = secure_random.randrange(len(chunks))
        chunks[uppercase_index] = chunks[uppercase_index].capitalize()

        # Add two different digits to satisfy the number requirement.
        digits = secure_random.sample(list(string.digits), 2)
        number = "".join(digits)

        # Use readable symbols between chunks.
        separators = choose_separator_symbols(chunk_count - 1)

        password_parts = [chunks[0]]

        for index in range(1, chunk_count):

            password_parts.append(separators[index - 1])

            # Put the number near the middle, but count it in the exact length.
            if index == chunk_count // 2:

                password_parts.append(number)

            password_parts.append(chunks[index])

        password = "".join(password_parts)

        if password_meets_policy(password, requested_length):

            return password

    raise RuntimeError("Could not generate a password that meets the policy.")


# Ask user about the exact number of characters.
user_input = input("What exact length do you want for your password? ")


# Check that the input is a number and meets the strict minimum.
while True:

    try: # if user input is not number, it will raise an error and go to except block

        characters_number = int(user_input)

        if characters_number < minimum_length:

            print("Your number should be at least 16.")

            user_input = input("Please, Enter your number again: ")

        else: # if user input is valid, it will break the loop and continue

            break

    except ValueError: # if user input is not number, it will raise an error and go to except block

        print("Please, Enter numbers only.")

        user_input = input("What exact length do you want for your password? ")


# Generate and print the password.
password = make_memorable_password(characters_number)
print("Strong Password: ", password)
