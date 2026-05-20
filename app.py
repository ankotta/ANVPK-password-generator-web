import secrets
import string
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

secure_random = secrets.SystemRandom()

minimum_length = 16
symbols = list("!#$%&*?-_.:~")
banned_characters = {" ", "@", "\"", ","}

onsets = [
    "b", "br", "c", "ch", "cl", "cr", "d", "dr", "f", "fl", "fr",
    "g", "gl", "gr", "h", "j", "k", "l", "m", "n", "p", "pl", "pr",
    "r", "s", "sh", "sl", "sm", "sn", "sp", "st", "t", "tr",
    "v", "w", "z"
]

vowels = ["a", "e", "i", "o", "u", "ae", "ai", "ea", "ee", "oa", "oo"]

codas = [
    "", "b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t",
    "ck", "ld", "mp", "nd", "ng", "nk", "nt", "rd", "sh", "sk", "st"
]


def make_syllable(length):
    choices = [
        onset + vowel + coda
        for onset in onsets
        for vowel in vowels
        for coda in codas
        if len(onset + vowel + coda) == length
    ]
    return secure_random.choice(choices)


def choose_chunk_count(password_length):
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
    return make_syllable(length)


def has_required_character_types(password):
    return (
        any(character in string.ascii_uppercase for character in password)
        and any(character in string.ascii_lowercase for character in password)
        and any(character in string.digits for character in password)
        and any(character in symbols for character in password)
    )


def choose_separator_symbols(count):
    shuffled_symbols = symbols.copy()
    secure_random.shuffle(shuffled_symbols)
    while len(shuffled_symbols) < count:
        shuffled_symbols.append(secure_random.choice(symbols))
    return shuffled_symbols[:count]


def has_banned_characters(password):
    return any(character in banned_characters for character in password)


def has_simple_repeating_pattern(password):
    lowered_password = password.lower()
    for chunk_size in range(1, 4):
        for index in range(len(lowered_password) - (chunk_size * 2) + 1):
            first_chunk = lowered_password[index:index + chunk_size]
            second_chunk = lowered_password[index + chunk_size:index + (chunk_size * 2)]
            if first_chunk == second_chunk:
                return True
    return False


def is_sequential(password, sequence):
    lowered_password = password.lower()
    for index in range(len(sequence) - 2):
        forward_sequence = sequence[index:index + 3]
        backward_sequence = forward_sequence[::-1]
        if forward_sequence in lowered_password or backward_sequence in lowered_password:
            return True
    return False


def password_meets_policy(password, requested_length):
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
    for _ in range(1000):
        chunk_count = choose_chunk_count(requested_length)
        chunk_lengths = choose_chunk_lengths(requested_length, chunk_count)
        chunks = [make_fake_word(length) for length in chunk_lengths]
        uppercase_index = secure_random.randrange(len(chunks))
        chunks[uppercase_index] = chunks[uppercase_index].capitalize()
        digits = secure_random.sample(list(string.digits), 2)
        number = "".join(digits)
        separators = choose_separator_symbols(chunk_count - 1)
        password_parts = [chunks[0]]
        for index in range(1, chunk_count):
            password_parts.append(separators[index - 1])
            if index == chunk_count // 2:
                password_parts.append(number)
            password_parts.append(chunks[index])
        password = "".join(password_parts)
        if password_meets_policy(password, requested_length):
            return password
    raise RuntimeError("Could not generate a password that meets the policy.")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    length = data.get("length")

    if length is None:
        return jsonify({"error": "Length is required."}), 400

    try:
        length = int(length)
    except (ValueError, TypeError):
        return jsonify({"error": "Length must be a number."}), 400

    if length < minimum_length:
        return jsonify({"error": f"Length must be at least {minimum_length}."}), 400

    try:
        password = make_memorable_password(length)
        return jsonify({"password": password})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
