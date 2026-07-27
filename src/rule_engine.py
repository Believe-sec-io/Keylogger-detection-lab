class RuleEngine:
    """
    Analyse les informations d'un processus
    et retourne un score de risque.
    """

    def evaluate(self, process):
        score = 0
        reasons = []

        path = process.get("path", "").lower()
        name = process.get("name", "").lower()

        # Règle 1 : exécution depuis un dossier temporaire
        if "temp" in path:
            score += 40
            reasons.append("Running from temporary directory")

        # Règle 2 : exécution depuis AppData
        if "appdata" in path:
            score += 30
            reasons.append("Running from AppData")

        # Détermination du niveau de risque
        if score >= 70:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": score,
            "level": level,
            "reasons": reasons
        }
