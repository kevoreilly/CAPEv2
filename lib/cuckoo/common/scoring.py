# =============================================================================
# Helper function to prevent code duplication for generic scoring.
# =============================================================================
def _calculate_generic_score(matched: list) -> float:
    """Calculates a generic score based on a list of matched signatures."""
    score = 0.0
    for match in matched:
        # We apply the 'maximum' attribute if present in the signature.
        # Check for key existence and that the value is not None to handle the case where maximum could be 0.
        if "maximum" in match and match["maximum"] is not None:
            score = max(score, match["maximum"])
            continue  # Skip to next signature

        if match["severity"] == 1:
            score += match["weight"] * 0.5 * (match["confidence"] / 100.0)
        else:
            score += match["weight"] * (match["severity"] - 1) * (match["confidence"] / 100.0)

    # Clamp the score between 0.0 and 10.0 using a common Python idiom.
    score = max(0.0, min(score, 10.0))

    return score


# =============================================================================
# Main scoring function.
# =============================================================================
def calc_scoring(results: dict, matched: list):
    """
    Calculate the final malware score and status based on the analysis results and matched signatures.

    The scoring is determined by the type of file and the categories of signatures it triggers. The methodology is as follows:
    1. Malicious-Known: The file is detected by YARA.
        - Score: 10/10 (Malicious)
    2. Malicious-Unknown: The file triggers signatures with specific malicious categories.
        - Categories: ["malware", "ransomware", "infostealer", "rat", "trojan", "rootkit", "bootkit", "wiper", "banker", "bypass", "anti-sandbox", "keylogger"]
        - Score: 7-9/10 (Malicious)
    3. Suspicious-Unknown: The file triggers signatures with specific suspicious categories.
        - Categories: ["network", "encryption", "anti-vm", "anti-analysis", "anti-av", "anti-debug", "anti-emulation", "persistence", "stealth", "discovery", "injection", "generic", "account", "bot", "browser", "allocation", "command", "execution"]
        - Score: 4-6/10 (Suspicious)
    4. Benign: The file is likely trusted and digitally signed.
        - Score: 0-3/10 (Benign)
    5. Undetected/Failed: The file does not trigger any signatures.
        - Score: 0/10 (Undetected/Failed)

    Parameters:
    results (dict): The analysis results containing details about the file and its behavior.
    matched (list): A list of matched signatures with their categories, severity, confidence, and weight.

    Returns:
    tuple: A tuple containing the final malware score (float) and the status (str).
    """
    finalMalscore = 0.0
    status = None
    # Identify the analysis category (file or url).
    category = results.get("target", {}).get("category")
    fileType = results.get("target", {}).get("file", {}).get("type")

    # IF THE ANALYSIS IS OF URL TYPE, we use the generic scoring logic
    if category == "url":
        # Calculate score using the helper function
        finalMalscore = _calculate_generic_score(matched)

        # We assign a status based on the score
        if finalMalscore >= 7.0:
            status = "Malicious"
        elif finalMalscore >= 4.0:
            status = "Suspicious"
        elif finalMalscore > 0.0:
            status = "Clean"
        else:
            status = "Undetected"

        return finalMalscore, status

    if not fileType:
        return finalMalscore, status

    if "executable" in fileType:
        # We have 5 methodologies
        # 1. The file is Malicious-Known (The sample is detected by YARA)
        # ... (and so on, this logic is specific to executables)
        tempScore1 = 0.0
        tempScore2 = 0.0
        is_maliciousCategoryHit = False
        is_suspiciousCategoryHit = False
        is_detected = False

        # CAPE uses signtool.exe utility to verify the digital signature embedded in the PE file.
        is_digital_signauture_verified = (
            results.get("target", {}).get("file", {}).get("pe", {}).get("guest_signers", {}).get("aux_valid", False)
        )

        maliciousCategories = [
            "malware", "ransomware", "infostealer", "rat", "trojan", "rootkit", "bootkit", "wiper", "banker",
            "bypass", "anti-sandbox", "keylogger",
        ]

        suspiciousCategories = [
            "network", "encryption", "anti-vm", "anti-analysis", "anti-av", "anti-debug", "anti-emulation",
            "persistence", "stealth", "discovery", "injection", "generic", "account", "bot", "browser",
            "allocation", "command", "execution",
        ]

        for detection in results.get("detections", []):
            if any("Yara" in detail for detail in detection.get("details", [])):
                is_detected = True

        for matchedSig in matched:
            if set(matchedSig.get("categories", [])) & set(maliciousCategories):
                if matchedSig["confidence"] > 70:
                    is_maliciousCategoryHit = True
                    matchedSig["weight"] = 4
                    if matchedSig["severity"] == 1:
                        tempScore1 += matchedSig["weight"] * 0.5 * (matchedSig["confidence"] / 100.0)
                    else:
                        tempScore1 += matchedSig["weight"] * (matchedSig["severity"] - 1) * (matchedSig["confidence"] / 100.0)

            if set(matchedSig.get("categories", [])) & set(suspiciousCategories):
                is_suspiciousCategoryHit = True
                if matchedSig["severity"] == 1:
                    tempScore2 += matchedSig["weight"] * 0.5 * (matchedSig["confidence"] / 100.0)
                else:
                    tempScore2 += matchedSig["weight"] * (matchedSig["severity"] - 1) * (matchedSig["confidence"] / 100.0)

        # 1. Malicious-Known
        if is_detected:
            status = "Malicious"
            finalMalscore = 10.0

        # 2. Malicious-Unknown
        elif is_maliciousCategoryHit:
            finalMalscore = tempScore1
            status = "Malicious"
            if 7.0 < finalMalscore < 9.0:
                pass
            elif finalMalscore >= 9.0:
                finalMalscore = 9.0
            elif finalMalscore < 7.0:
                finalMalscore = 7.0

        # 3. Suspicious-Unknown
        elif is_suspiciousCategoryHit:
            finalMalscore = tempScore2
            if is_digital_signauture_verified:
                finalMalscore = 0.0
                status = "Clean"
            elif finalMalscore < 4.0:
                status = "Clean"
            elif finalMalscore >= 6.0:
                finalMalscore = 6.0
                status = "Suspicious"
            elif 4.0 <= finalMalscore < 6.0:
                status = "Suspicious"

        # 5. Undetected/Failed
        else:
            finalMalscore = 0
            if results.get("behavior", {}).get("processtree", []):
                status = "Undetected"
            else:
                status = "Failed"
    else:
        # For all other non-executable file types, use the generic scoring logic
        finalMalscore = _calculate_generic_score(matched)
        # Note: The original logic did not assign a status here, so we keep that behavior.

    return finalMalscore, status
