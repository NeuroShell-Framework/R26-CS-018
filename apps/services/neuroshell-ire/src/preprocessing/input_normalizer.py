# NeuroShell IRE — Input Normalizer
# Normalize raw user input before intent classification

import re
import unicodedata
from src.utils.logging_config import get_logger


class InputNormalizer:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.TERM_STANDARDIZATIONS = [
            (re.compile(r"\bsyn scan\b", re.IGNORECASE), "SYN stealth scan"),
            (re.compile(r"\bping sweep\b", re.IGNORECASE), "ICMP discovery scan"),
            (re.compile(r"\bstealthy sweep\b", re.IGNORECASE), "stealth ICMP discovery scan"),
            (re.compile(r"\bport scan\b", re.IGNORECASE), "network port scan"),
            (re.compile(r"\bbrute\s*force\b", re.IGNORECASE), "brute force attack"),
            (re.compile(r"\benum(erate|eration)?\b", re.IGNORECASE), "enumeration"),
            (re.compile(r"\brecon(naissance)?\b", re.IGNORECASE), "reconnaissance"),
            (re.compile(r"\bos detect(ion)?\b", re.IGNORECASE), "OS detection"),
            (re.compile(r"\bversion detect(ion)?\b", re.IGNORECASE), "version detection"),
            (re.compile(r"\bweb scan\b", re.IGNORECASE), "web directory scan"),
            (re.compile(r"\bdir\s*bust(ing)?\b", re.IGNORECASE), "directory bruteforce"),
            (re.compile(r"\bfuzz(ing)?\b", re.IGNORECASE), "fuzzing"),
            (re.compile(r"\bpwn\b", re.IGNORECASE), "exploit"),
            (re.compile(r"\bbox\b", re.IGNORECASE), "host"),
            (re.compile(r"\bpop\s*a\s*shell\b", re.IGNORECASE), "gain shell access"),
            (re.compile(r"\bget\s*root\b", re.IGNORECASE), "privilege escalation"),
            (re.compile(r"\bprivesc\b", re.IGNORECASE), "privilege escalation"),
            (re.compile(r"\bloot\b", re.IGNORECASE), "extract credentials"),
            (re.compile(r"\bdump\s*creds?\b", re.IGNORECASE), "extract credentials"),
            (re.compile(r"\bspray\b", re.IGNORECASE), "password spray attack"),
        ]
        self.GEMMA_TOKENS = [
            '</' + 'think>',
            '<' + 'think>',
            '<|' + 'think|>',
        ]

    def _strip_control_chars(self, text: str) -> str:
        text = text.replace("\x00", "")
        text = text.replace("\t", " ")
        text = text.replace("\n", " ")
        text = "".join(ch for ch in text if ord(ch) >= 32)
        return text

    def normalize(self, text: str) -> str:
        if not text or not text.strip():
            raise ValueError("Input text cannot be empty")

        text = text.strip()

        text = unicodedata.normalize("NFKC", text)

        text = self._strip_control_chars(text)

        for token in self.GEMMA_TOKENS:
            text = text.replace(token, "")

        text = re.sub(r"\s+", " ", text)

        original_len = len(text)
        for pattern, replacement in self.TERM_STANDARDIZATIONS:
            text = pattern.sub(replacement, text)

        text = text.strip()

        self.logger.debug(
            "input_normalized",
            original_length=original_len,
            normalized_length=len(text),
        )

        return text
