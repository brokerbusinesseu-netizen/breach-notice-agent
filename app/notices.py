"""Draft notices required by GDPR Art. 33(3) (authority) and Art. 34(2) (data subjects), in PL and EN."""
from __future__ import annotations

from .models import Incident
from .risk import AUTHORITY, AUTHORITY_AND_SUBJECTS, NONE, Assessment

CATEGORY_LABELS = {
    "en": {
        "basic_identity": "name and basic identity data",
        "contact": "contact details",
        "location": "location data",
        "national_id": "national identification numbers",
        "financial": "financial data",
        "credentials": "login credentials",
        "health": "health data",
        "special_category": "special category data (Art. 9)",
        "criminal": "data on criminal convictions",
    },
    "pl": {
        "basic_identity": "imię, nazwisko i podstawowe dane identyfikacyjne",
        "contact": "dane kontaktowe",
        "location": "dane o lokalizacji",
        "national_id": "numery identyfikacyjne (np. PESEL)",
        "financial": "dane finansowe",
        "credentials": "dane logowania",
        "health": "dane o zdrowiu",
        "special_category": "dane szczególnych kategorii (art. 9)",
        "criminal": "dane o wyrokach skazujących",
    },
}

CONSEQUENCES = {
    "en": {
        "contact": "phishing and unwanted contact using your details",
        "basic_identity": "impersonation or identity fraud",
        "location": "tracking of your whereabouts",
        "national_id": "identity theft, for example loans taken in your name",
        "financial": "financial fraud or unauthorised payments",
        "credentials": "unauthorised access to your accounts",
        "health": "disclosure of sensitive health information and discrimination",
        "special_category": "disclosure of sensitive information and discrimination",
        "criminal": "reputational harm and discrimination",
    },
    "pl": {
        "contact": "wyłudzanie danych (phishing) i niechciany kontakt z użyciem Państwa danych",
        "basic_identity": "podszywanie się pod Państwa osobę",
        "location": "śledzenie miejsca pobytu",
        "national_id": "kradzież tożsamości, np. zaciągnięcie zobowiązań w Państwa imieniu",
        "financial": "oszustwa finansowe lub nieautoryzowane płatności",
        "credentials": "nieuprawniony dostęp do kont",
        "health": "ujawnienie wrażliwych informacji o zdrowiu i dyskryminacja",
        "special_category": "ujawnienie wrażliwych informacji i dyskryminacja",
        "criminal": "naruszenie reputacji i dyskryminacja",
    },
}

ADVICE = {
    "en": {
        "credentials": "Change your password now and enable two-factor authentication.",
        "financial": "Monitor your bank account and cards, and contact your bank if you see anything unusual.",
        "national_id": "Consider reserving your national ID number and watch for credit checks you did not request.",
        "contact": "Be careful with messages that mention this incident and never share codes or passwords.",
    },
    "pl": {
        "credentials": "Zmień hasło i włącz uwierzytelnianie dwuskładnikowe.",
        "financial": "Obserwuj rachunek i karty, a w razie niepokojących operacji skontaktuj się z bankiem.",
        "national_id": "Rozważ zastrzeżenie numeru PESEL i zwracaj uwagę na zapytania kredytowe, których nie inicjowałeś.",
        "contact": "Uważaj na wiadomości powołujące się na ten incydent i nigdy nie podawaj kodów ani haseł.",
    },
}


def _join(items: list[str]) -> str:
    return ", ".join(items)


def _labels(inc: Incident, lang: str) -> str:
    return _join([CATEGORY_LABELS[lang][c] for c in inc.data_categories])


def _consequences(inc: Incident, lang: str) -> str:
    return _join(dict.fromkeys(CONSEQUENCES[lang][c] for c in inc.data_categories))


def _advice(inc: Incident, lang: str) -> str:
    items = [ADVICE[lang][c] for c in inc.data_categories if c in ADVICE[lang]]
    return " ".join(dict.fromkeys(items))


def authority_notice(inc: Incident, a: Assessment, lang: str) -> dict:
    when = inc.discovered_at.isoformat()
    measures = inc.measures_taken or ("none recorded yet" if lang == "en" else "brak zapisanych działań")
    if lang == "en":
        body = (
            f"Notification of a personal data breach (Art. 33 GDPR)\n\n"
            f"Controller: {inc.organisation}\n"
            f"Reference: {inc.incident_id}\n"
            f"Date and time the controller became aware: {when}\n\n"
            f"1. Nature of the breach (Art. 33(3)(a)): {inc.breach_type}. {inc.description}\n"
            f"   Categories of data: {_labels(inc, 'en')}.\n"
            f"   Approximate number of data subjects: {inc.subjects_count}.\n"
            f"2. Contact point (Art. 33(3)(b)): Data Protection Officer, {inc.dpo_email}.\n"
            f"3. Likely consequences (Art. 33(3)(c)): {_consequences(inc, 'en')}.\n"
            f"4. Measures taken or proposed (Art. 33(3)(d)): {measures}.\n"
        )
        if a.late:
            body += f"\nReasons for the delay (Art. 33(1)): {inc.delay_reason or 'TO BE COMPLETED BY THE DPO'}\n"
        return {"subject": f"[{inc.incident_id}] Personal data breach notification", "body": body}
    body = (
        f"Zgłoszenie naruszenia ochrony danych osobowych (art. 33 RODO)\n\n"
        f"Administrator: {inc.organisation}\n"
        f"Numer sprawy: {inc.incident_id}\n"
        f"Data i godzina stwierdzenia naruszenia: {when}\n\n"
        f"1. Charakter naruszenia (art. 33 ust. 3 lit. a): {inc.breach_type}. {inc.description}\n"
        f"   Kategorie danych: {_labels(inc, 'pl')}.\n"
        f"   Przybliżona liczba osób: {inc.subjects_count}.\n"
        f"2. Punkt kontaktowy (art. 33 ust. 3 lit. b): Inspektor Ochrony Danych, {inc.dpo_email}.\n"
        f"3. Możliwe konsekwencje (art. 33 ust. 3 lit. c): {_consequences(inc, 'pl')}.\n"
        f"4. Zastosowane lub proponowane środki (art. 33 ust. 3 lit. d): {measures}.\n"
    )
    if a.late:
        body += f"\nPrzyczyny opóźnienia (art. 33 ust. 1): {inc.delay_reason or 'DO UZUPEŁNIENIA PRZEZ IOD'}\n"
    return {"subject": f"[{inc.incident_id}] Zgłoszenie naruszenia ochrony danych", "body": body}


def subject_notice(inc: Incident, lang: str) -> dict:
    measures = inc.measures_taken
    if lang == "en":
        body = (
            f"Dear Sir or Madam,\n\n"
            f"{inc.organisation} is writing to inform you about a personal data breach that may affect you.\n\n"
            f"What happened: {inc.description}\n"
            f"What data were involved: {_labels(inc, 'en')}.\n"
            f"What this may mean for you: {_consequences(inc, 'en')}.\n"
            f"What we have done: {measures or 'we are investigating and securing the systems concerned'}.\n"
            f"What you can do: {_advice(inc, 'en') or 'Stay alert for unusual messages or activity.'}\n\n"
            f"Contact: Data Protection Officer, {inc.dpo_email}.\n\n{inc.organisation}\n"
        )
        return {"subject": f"Important: personal data incident at {inc.organisation}", "body": body}
    body = (
        f"Szanowni Państwo,\n\n"
        f"{inc.organisation} informuje o naruszeniu ochrony danych osobowych, które może Państwa dotyczyć.\n\n"
        f"Co się stało: {inc.description}\n"
        f"Jakich danych dotyczy naruszenie: {_labels(inc, 'pl')}.\n"
        f"Możliwe konsekwencje dla Państwa: {_consequences(inc, 'pl')}.\n"
        f"Co zrobiliśmy: {measures or 'badamy sprawę i zabezpieczamy systemy, których dotyczy incydent'}.\n"
        f"Co możecie Państwo zrobić: {_advice(inc, 'pl') or 'Zachowaj ostrożność wobec nietypowych wiadomości i aktywności.'}\n\n"
        f"Kontakt: Inspektor Ochrony Danych, {inc.dpo_email}.\n\n{inc.organisation}\n"
    )
    return {"subject": f"Ważne: incydent ochrony danych w {inc.organisation}", "body": body}


def sms_text(inc: Incident, lang: str, limit: int = 160) -> str:
    """Short SMS draft (ASCII, max 160 chars). Drafted only, not sent in this version."""
    tail = f" IOD: {inc.dpo_email}"
    if lang == "en":
        head = "{org}: data incident {id}. Check your e-mail for details and change your password."
    else:
        head = "{org}: incydent danych {id}. Sprawdz e-mail i zmien haslo."
    org = inc.organisation
    for _ in range(200):
        text = head.format(org=org, id=inc.incident_id) + tail
        if len(text) <= limit:
            return text
        org = org[:-1]
    return (head.format(org="", id=inc.incident_id) + tail)[:limit]


def build_drafts(inc: Incident, a: Assessment) -> dict:
    """Return the set of drafts that the assessment calls for. Empty if no notification is needed."""
    if a.outcome == NONE:
        return {}
    drafts: dict = {
        "authority_pl": authority_notice(inc, a, "pl"),
        "authority_en": authority_notice(inc, a, "en"),
    }
    if a.outcome == AUTHORITY_AND_SUBJECTS:
        drafts["subject_pl"] = subject_notice(inc, "pl")
        drafts["subject_en"] = subject_notice(inc, "en")
        drafts["sms_pl"] = {"subject": "", "body": sms_text(inc, "pl")}
        drafts["sms_en"] = {"subject": "", "body": sms_text(inc, "en")}
    return drafts
