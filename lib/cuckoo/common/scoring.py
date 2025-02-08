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
    fileType = results.get("target", {}).get("file", {}).get("type")

    if not fileType:
        return finalMalscore, status

    if "executable" in fileType:
        # We have 5 methodologies
        # 1. The file is Malicious-Known (The sample is detected by YARA)
        ## score 10/10 (Malicious)
        # =======================================================================================================#
        # 2. If the file is Malicious-Unknown
        ## triggered some signatures that has specific malicious categories such as:
        ## ["malware", "ransomware", "infostealer", "rat", "trojan", "rootkit", "bootkit", "wiper", "banker",
        ## "bypass", "anti-sandbox", "keylogger"]
        ## score [7-9]/10 (Malicious)
        # =======================================================================================================#
        # 3. If the file is Suspicious-Unknown
        ## triggered some signatures that has specific suspicious categories such as:
        ## ["network", "encryption", "anti-vm", "anti-analysis", "anti-av", "anti-debug", "anti-emulation",
        ## "persistence", "stealth", "discovery", "injection", "generic",  "account", "bot", "browser",
        #  "allocation", "command"]
        ## score[4-6]/10 (Suspicious)
        # =======================================================================================================#
        # 4. If the file is benign
        ## Likely all trusted files are digitally signed.
        ## score [0-3]/10 (benign)
        # =======================================================================================================#
        # 5. If the file doesn't trigger any signatures
        ## The file is undetected/failed
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
            "malware",
            "ransomware",
            "infostealer",
            "rat",
            "trojan",
            "rootkit",
            "bootkit",
            "wiper",
            "banker",
            "bypass",
            "anti-sandbox",
            "keylogger",
        ]

        suspiciousCategories = [
            "network",
            "encryption",
            "anti-vm",
            "anti-analysis",
            "anti-av",
            "anti-debug",
            "anti-emulation",
            "persistence",
            "stealth",
            "discovery",
            "injection",
            "generic",
            "account",
            "bot",
            "browser",
            "allocation",
            "command",
            "execution",
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

        # 1. The file is Malicious-Known (The sample is detected by YARA)
        ## score 10/10 (Malicious)
        if is_detected:
            status = "Malicious"
            finalMalscore = 10.0

        # 2. If the file is Malicious-Unknown
        ## triggered some signatures that has specific malicious categories such as:
        ## ["malware", "ransomware", "infostealer", "rat", "trojan", "rootkit", "bootkit", "wiper", "banker",
        ## "bypass", "anti-sandbox", "keylogger"]
        ## score [7-9]/10 (Malicious)
        elif is_maliciousCategoryHit:
            finalMalscore = tempScore1
            status = "Malicious"
            ## Include numbers between that range
            if 7.0 < finalMalscore < 9.0:
                pass
            elif finalMalscore >= 9.0:
                finalMalscore = 9.0
            elif finalMalscore < 7.0:
                finalMalscore = 7.0

        # 3. If the file is Suspicious-Unknown
        ## triggered some signatures that has specific suspicious categories such as:
        ## ["network", "encryption", "anti-vm", "anti-analysis", "anti-av", "anti-debug", "anti-emulation",
        ## "persistence", "stealth", "discovery", "injection", "generic",  "account", "bot", "browser",
        #  "allocation", "command"]
        ## score[4-6]/10 (Suspicious)
        elif is_suspiciousCategoryHit:
            finalMalscore = tempScore2

            # 4. If the file is benign
            ## Likely all trusted files are digitally signed.
            ## score [0-3]/10 (benign)
            if is_digital_signauture_verified:
                finalMalscore = 0.0
                status = "Clean"

            elif finalMalscore < 4.0:
                status = "Clean"

            ## Include numbers between that range
            elif 4.0 < finalMalscore < 6.0:
                status = "Suspicious"
            elif finalMalscore == 4:
                finalMalscore = 4
                status = "Suspicious"
            elif finalMalscore >= 6.0:
                finalMalscore = 6.0
                status = "Suspicious"

        # 5. If the file doesn't trigger any signatures
        ## The file is undetected/failed
        else:
            finalMalscore = 0
            if results.get("behavior", {}).get("processtree", []):
                status = "Undetected"
            else:
                status = "Failed"
    else:
        for match in matched:
            if match["severity"] == 1:
                finalMalscore += match["weight"] * 0.5 * (match["confidence"] / 100.0)
            else:
                finalMalscore += match["weight"] * (match["severity"] - 1) * (match["confidence"] / 100.0)
        if finalMalscore > 10.0:
            finalMalscore = 10.0
        if finalMalscore < 0.0:
            finalMalscore = 0.0

    return finalMalscore, status
