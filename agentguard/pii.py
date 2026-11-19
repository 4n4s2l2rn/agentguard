"""PII detection and anonymization on egress, using Microsoft Presidio."""
from __future__ import annotations

from functools import lru_cache

ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", "PERSON"]


@lru_cache(maxsize=1)
def _engines():
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    import tldextract

    # offline: use the bundled public-suffix snapshot instead of downloading it
    offline = tldextract.TLDExtract(suffix_list_urls=())
    tldextract.extract = offline
    tldextract.tldextract.extract = offline

    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    })
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
    return analyzer, AnonymizerEngine()


def redact(text: str, threshold: float = 0.4) -> tuple[str, list[str]]:
    """Replace detected PII with <ENTITY_TYPE> placeholders. Returns (text, entity types found)."""
    analyzer, anonymizer = _engines()
    results = [r for r in analyzer.analyze(text=text, entities=ENTITIES, language="en")
               if r.score >= threshold]
    if not results:
        return text, []
    out = anonymizer.anonymize(text=text, analyzer_results=results)
    return out.text, sorted({r.entity_type for r in results})
