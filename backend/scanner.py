import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from playwright.sync_api import sync_playwright
import tldextract


# ============================================================
# ROOT DOMAIN
# ============================================================

def get_root_domain(url):
    extracted = tldextract.extract(url)

    if not extracted.domain or not extracted.suffix:
        return ""

    return f"{extracted.domain}.{extracted.suffix}"


# ============================================================
# THIRD-PARTY CLASSIFICATION
# ============================================================

def classify_third_party(domain):

    domain = domain.lower()

    analytics_services = [
        "google-analytics.com",
        "googletagmanager.com",
        "analytics.google.com",
        "matomo"
    ]

    advertising_services = [
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "facebook.net",
        "ads."
    ]

    social_services = [
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com"
    ]

    payment_services = [
        "stripe.com",
        "paypal.com",
        "razorpay.com",
        "paytm.com"
    ]

    cdn_services = [
        "cloudflare.com",
        "cdnjs.cloudflare.com",
        "jsdelivr.net",
        "unpkg.com"
    ]

    security_services = [
        "recaptcha.net",
        "hcaptcha.com"
    ]

    for service in analytics_services:
        if service in domain:
            return "analytics"

    for service in advertising_services:
        if service in domain:
            return "advertising"

    for service in social_services:
        if service in domain:
            return "social_media"

    for service in payment_services:
        if service in domain:
            return "payment"

    for service in cdn_services:
        if service in domain:
            return "cdn"

    for service in security_services:
        if service in domain:
            return "security"

    return "unknown"


# ============================================================
# COOKIE CLASSIFICATION
# ============================================================

def classify_cookie(cookie_name):

    name = cookie_name.lower()

    analytics_keywords = [
        "_ga",
        "_gid",
        "_gat",
        "analytics"
    ]

    advertising_keywords = [
        "_fbp",
        "doubleclick",
        "advert",
        "ads",
        "tracking"
    ]

    session_keywords = [
        "session",
        "sessionid",
        "phpsessid",
        "jsessionid"
    ]

    for keyword in analytics_keywords:
        if keyword in name:
            return "analytics"

    for keyword in advertising_keywords:
        if keyword in name:
            return "advertising"

    for keyword in session_keywords:
        if keyword in name:
            return "session"

    return "unknown"


# ============================================================
# PRIVACY TRANSPARENCY SCORE
# ============================================================

def calculate_transparency_score(scan_result):

    if scan_result.get("scan_status") != "success":

        return {
            "privacy_transparency_score": None,
            "transparency_reasons": [
                "Website scan was blocked or incomplete."
            ]
        }

    score = 0
    reasons = []

    policy_analysis = scan_result.get(
        "privacy_policy_analysis",
        {}
    )

    if not policy_analysis.get("policy_found", False):

        return {
            "privacy_transparency_score": 0,
            "transparency_reasons": [
                "No privacy policy could be found."
            ]
        }

    # Privacy policy exists
    score += 20
    reasons.append("Privacy policy found.")

    findings = policy_analysis.get(
        "policy_findings",
        []
    )

    # Data collection
    if "data_collection" in findings:

        score += 15

        reasons.append(
            "Data collection practices are described."
        )

    # Data sharing
    if "data_sharing" in findings:

        score += 15

        reasons.append(
            "Data sharing practices are mentioned."
        )

    # Tracking
    if "tracking" in findings:

        score += 10

        reasons.append(
            "Tracking technologies are disclosed."
        )

    # Data retention
    if "data_retention" in findings:

        score += 15

        reasons.append(
            "Data retention information is provided."
        )

    # User rights
    if "user_rights" in findings:

        score += 15

        reasons.append(
            "User privacy rights are described."
        )

    # Cookies
    if "cookies" in findings:

        score += 10

        reasons.append(
            "Cookie usage is disclosed."
        )

    score = min(score, 100)

    return {
        "privacy_transparency_score": score,
        "transparency_reasons": reasons
    }


# ============================================================
# PRIVACY RISK SCORE
# ============================================================

def calculate_privacy_risk(scan_result):

    if scan_result.get("scan_status") != "success":

        return {
            "privacy_risk_score": None,
            "privacy_risk_level": "Not Available",
            "privacy_risk_reasons": [
                "Website scan was blocked or incomplete."
            ]
        }

    score = 0
    reasons = []

    # HTTPS check
    if not scan_result.get("https", False):

        score += 30

        reasons.append(
            "Website does not use HTTPS."
        )

    # ========================================================
    # COOKIE ANALYSIS
    # ========================================================

    cookie_categories = scan_result.get(
        "cookie_categories",
        {}
    )

    analytics_count = 0
    advertising_count = 0
    unknown_count = 0

    for category in cookie_categories.values():

        if category == "analytics":
            analytics_count += 1

        elif category == "advertising":
            advertising_count += 1

        elif category == "unknown":
            unknown_count += 1

    # Analytics cookies
    if analytics_count > 0:

        score += analytics_count * 5

        reasons.append(
            f"{analytics_count} analytics cookie(s) detected."
        )

    # Advertising cookies
    if advertising_count > 0:

        score += advertising_count * 10

        reasons.append(
            f"{advertising_count} advertising cookie(s) detected."
        )

    # Unknown cookies
    if unknown_count > 0:

        score += unknown_count

        reasons.append(
            f"{unknown_count} cookie(s) could not be classified."
        )

    # ========================================================
    # THIRD-PARTY SERVICES
    # ========================================================

    third_party_categories = scan_result.get(
        "third_party_categories",
        {}
    )

    advertising_services = 0
    analytics_services = 0

    for category in third_party_categories.values():

        if category == "advertising":
            advertising_services += 1

        elif category == "analytics":
            analytics_services += 1

    # Analytics services
    if analytics_services > 0:

        score += analytics_services * 5

        reasons.append(
            f"{analytics_services} analytics service(s) detected."
        )

    # Advertising services
    if advertising_services > 0:

        score += advertising_services * 10

        reasons.append(
            f"{advertising_services} advertising service(s) detected."
        )

    # Limit score
    score = min(score, 100)

    # Determine risk level
    if score < 20:

        risk_level = "Low"

    elif score < 50:

        risk_level = "Medium"

    elif score < 75:

        risk_level = "High"

    else:

        risk_level = "Very High"

    return {
        "privacy_risk_score": score,
        "privacy_risk_level": risk_level,
        "privacy_risk_reasons": reasons
    }


# ============================================================
# FIND PRIVACY POLICY
# ============================================================

def find_privacy_policy(url, soup):

    possible_names = [
        "privacy policy",
        "privacy",
        "privacy notice",
        "data privacy",
        "data protection"
    ]

    # Check links on current page
    for link in soup.find_all("a"):

        link_text = link.get_text(
            " ",
            strip=True
        ).lower()

        href = link.get("href")

        if not href:
            continue

        for name in possible_names:

            if name in link_text:

                policy_url = urljoin(
                    url,
                    href
                )

                return policy_url

    # Try common privacy-policy URLs
    common_paths = [
        "/privacy-policy",
        "/privacy",
        "/privacy-policy/",
        "/privacy/"
    ]

    for path in common_paths:

        policy_url = urljoin(
            url,
            path
        )

        try:

            policy_response = requests.get(
                policy_url,
                timeout=5,
                headers={
                    "User-Agent": "Mozilla/5.0"
                }
            )

            if policy_response.status_code == 200:

                return policy_url

        except requests.RequestException:

            continue

    return None


# ============================================================
# FIND BUSINESS POLICIES
# ============================================================

def find_business_policies(url, soup):

    policies = {
        "contact": None,
        "return_refund": None,
        "shipping": None,
        "terms": None
    }

    keywords = {

        "contact": [
            "contact",
            "contact us",
            "customer support"
        ],

        "return_refund": [
            "return",
            "refund",
            "returns & refunds",
            "return policy"
        ],

        "shipping": [
            "shipping",
            "delivery",
            "shipping policy"
        ],

        "terms": [
            "terms",
            "terms and conditions",
            "terms of service"
        ]
    }

    links = soup.find_all(
        "a",
        href=True
    )

    for link in links:

        text = link.get_text(
            " ",
            strip=True
        ).lower()

        href = link.get("href")

        if not href:
            continue

        full_url = urljoin(
            url,
            href
        ).lower()

        for category, words in keywords.items():

            if policies[category] is None:

                for word in words:

                    if word in text or word in full_url:

                        policies[category] = urljoin(
                            url,
                            href
                        )

                        break

    return policies


# ============================================================
# ANALYZE PRIVACY POLICY
# ============================================================

def analyze_privacy_policy(policy_url):

    if not policy_url:

        return {
            "policy_found": False,
            "policy_text_length": 0,
            "policy_findings": []
        }

    try:

        response = requests.get(
            policy_url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if response.status_code != 200:

            return {
                "policy_found": False,
                "policy_text_length": 0,
                "policy_findings": []
            }

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # Remove elements that do not contain useful text
        for element in soup(
            ["script", "style", "noscript"]
        ):

            element.decompose()

        policy_text = soup.get_text(
            " ",
            strip=True
        ).lower()

        findings = []

        privacy_keywords = {

            "data_collection": [
                "collect personal data",
                "collect personal information",
                "information we collect",
                "data we collect"
            ],

            "data_sharing": [
                "share your information",
                "share personal data",
                "third parties",
                "third-party"
            ],

            "advertising": [
                "advertising",
                "advertisements",
                "targeted advertising"
            ],

            "tracking": [
                "tracking",
                "track your activity",
                "tracking technologies"
            ],

            "data_retention": [
                "retain your information",
                "data retention",
                "retain personal data"
            ],

            "user_rights": [
                "your rights",
                "right to access",
                "right to delete",
                "right to erasure"
            ],

            "cookies": [
                "cookies",
                "cookie policy"
            ]
        }

        for category, keywords in privacy_keywords.items():

            for keyword in keywords:

                if keyword in policy_text:

                    findings.append(category)

                    break

        return {
            "policy_found": True,
            "policy_text_length": len(policy_text),
            "policy_findings": findings
        }

    except requests.RequestException:

        return {
            "policy_found": False,
            "policy_text_length": 0,
            "policy_findings": []
        }


# ============================================================
# PLAYWRIGHT SCANNER
# ============================================================

def scan_with_playwright(url):

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        page = browser.new_page(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/154.0.0.0 Safari/537.36"
            )
        )

        try:

            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=30000
            )

            status_code = (
                response.status
                if response
                else None
            )

            # =================================================
            # BROWSER BLOCKED
            # =================================================

            if status_code in [403, 429]:

                return {
                    "url": page.url,
                    "title": page.title(),
                    "https": page.url.startswith(
                        "https://"
                    ),
                    "status_code": status_code,
                    "scan_status": "blocked"
                }

            # =================================================
            # OTHER HTTP ERROR
            # =================================================

            if status_code != 200:

                return {
                    "url": page.url,
                    "title": page.title(),
                    "https": page.url.startswith(
                        "https://"
                    ),
                    "status_code": status_code,
                    "scan_status": "http_error"
                }

            # =================================================
            # GET BROWSER-GENERATED HTML
            # =================================================

            html = page.content()

            soup = BeautifulSoup(
                html,
                "html.parser"
            )

            # =================================================
            # COOKIES
            # =================================================

            cookies = page.context.cookies()

            cookie_names = []

            cookie_categories = {}

            for cookie in cookies:

                cookie_name = cookie["name"]

                cookie_names.append(
                    cookie_name
                )

                cookie_categories[
                    cookie_name
                ] = classify_cookie(
                    cookie_name
                )

            # =================================================
            # THIRD-PARTY DOMAINS
            # =================================================

            base_domain = get_root_domain(
                page.url
            )

            third_party_domains = set()

            for tag in soup.find_all(
                ["a", "script", "img", "iframe"]
            ):

                attribute = (
                    tag.get("href")
                    or tag.get("src")
                )

                if attribute:

                    absolute_url = urljoin(
                        page.url,
                        attribute
                    )

                    domain = urlparse(
                        absolute_url
                    ).netloc.lower()

                    domain_root = get_root_domain(
                        absolute_url
                    )

                    if (
                        domain_root
                        and domain_root != base_domain
                    ):

                        third_party_domains.add(
                            domain
                        )

            # =================================================
            # CLASSIFY THIRD-PARTY DOMAINS
            # =================================================

            third_party_categories = {}

            for domain in third_party_domains:

                third_party_categories[
                    domain
                ] = classify_third_party(
                    domain
                )

            # =================================================
            # PRIVACY POLICY
            # =================================================

            privacy_policy_url = find_privacy_policy(
                page.url,
                soup
            )

            privacy_policy_analysis = (
                analyze_privacy_policy(
                    privacy_policy_url
                )
            )

            # =================================================
            # BUSINESS POLICIES
            # =================================================

            business_policies = find_business_policies(
                page.url,
                soup
            )

            # =================================================
            # RETURN RESULTS
            # =================================================

            return {

                "url": page.url,

                "title": page.title(),

                "https": page.url.startswith(
                    "https://"
                ),

                "status_code": status_code,

                "scan_status": "success",

                "privacy_policy_url": (
                    privacy_policy_url
                ),

                "privacy_policy_analysis": (
                    privacy_policy_analysis
                ),

                "links": len(
                    soup.find_all("a")
                ),

                "images": len(
                    soup.find_all("img")
                ),

                "scripts": len(
                    soup.find_all("script")
                ),

                "forms": len(
                    soup.find_all("form")
                ),

                "iframes": len(
                    soup.find_all("iframe")
                ),

                "cookies": cookie_names,

                "cookie_categories": (
                    cookie_categories
                ),

                "third_party_domains": sorted(
                    third_party_domains
                ),

                "business_policies": (
                    business_policies
                ),

                "third_party_categories": (
                    third_party_categories
                )
            }

        except Exception as e:

            return {

                "url": url,

                "title": None,

                "https": url.startswith(
                    "https://"
                ),

                "status_code": None,

                "scan_status": "error",

                "error": str(e)
            }

        finally:

            browser.close()


# ============================================================
# MAIN WEBSITE SCANNER
# ============================================================

def scan_website(url):

    # Make sure URL has a protocol
    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url

    try:

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        # ====================================================
        # DETERMINE SCAN STATUS
        # ====================================================

        if response.status_code in [403, 429]:

            print(
                "Requests scanner was blocked. "
                "Trying Playwright..."
            )

            return scan_with_playwright(
                url
            )

        elif response.status_code != 200:

            scan_status = "http_error"

        else:

            scan_status = "success"

        # ====================================================
        # COOKIE ANALYSIS
        # ====================================================

        cookies = response.cookies

        cookie_names = []

        cookie_categories = {}

        for cookie in cookies:

            cookie_names.append(
                cookie.name
            )

            cookie_categories[
                cookie.name
            ] = classify_cookie(
                cookie.name
            )

        # ====================================================
        # PARSE HTML
        # ====================================================

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # ====================================================
        # FIND PRIVACY POLICY
        # ====================================================

        privacy_policy_url = find_privacy_policy(
            response.url,
            soup
        )

        privacy_policy_analysis = (
            analyze_privacy_policy(
                privacy_policy_url
            )
        )

        # ====================================================
        # FIND BUSINESS POLICIES
        # ====================================================

        business_policies = find_business_policies(
            response.url,
            soup
        )

        # ====================================================
        # GET WEBSITE ROOT DOMAIN
        # ====================================================

        base_domain = get_root_domain(
            response.url
        )

        # ====================================================
        # WEBSITE TITLE
        # ====================================================

        title = (

            soup.title.string.strip()

            if soup.title
            and soup.title.string

            else "No title"
        )

        # ====================================================
        # BASIC HTML ELEMENTS
        # ====================================================

        links = soup.find_all("a")

        images = soup.find_all("img")

        scripts = soup.find_all("script")

        forms = soup.find_all("form")

        iframes = soup.find_all("iframe")

        # ====================================================
        # FIND THIRD-PARTY RESOURCES
        # ====================================================

        third_party_domains = set()

        # ====================================================
        # CHECK LINKS
        # ====================================================

        for link in links:

            href = link.get("href")

            if href:

                absolute_url = urljoin(
                    response.url,
                    href
                )

                parsed = urlparse(
                    absolute_url
                )

                domain = parsed.netloc.lower()

                if domain:

                    domain_root = get_root_domain(
                        absolute_url
                    )

                    if (
                        domain_root
                        and domain_root != base_domain
                    ):

                        third_party_domains.add(
                            domain
                        )

        # ====================================================
        # CHECK SCRIPTS
        # ====================================================

        for script in scripts:

            src = script.get("src")

            if src:

                absolute_url = urljoin(
                    response.url,
                    src
                )

                parsed = urlparse(
                    absolute_url
                )

                domain = parsed.netloc.lower()

                if domain:

                    domain_root = get_root_domain(
                        absolute_url
                    )

                    if (
                        domain_root
                        and domain_root != base_domain
                    ):

                        third_party_domains.add(
                            domain
                        )

        # ====================================================
        # CHECK IMAGES
        # ====================================================

        for image in images:

            src = image.get("src")

            if src:

                absolute_url = urljoin(
                    response.url,
                    src
                )

                parsed = urlparse(
                    absolute_url
                )

                domain = parsed.netloc.lower()

                if domain:

                    domain_root = get_root_domain(
                        absolute_url
                    )

                    if (
                        domain_root
                        and domain_root != base_domain
                    ):

                        third_party_domains.add(
                            domain
                        )

        # ====================================================
        # CHECK IFRAMES
        # ====================================================

        for iframe in iframes:

            src = iframe.get("src")

            if src:

                absolute_url = urljoin(
                    response.url,
                    src
                )

                parsed = urlparse(
                    absolute_url
                )

                domain = parsed.netloc.lower()

                if domain:

                    domain_root = get_root_domain(
                        absolute_url
                    )

                    if (
                        domain_root
                        and domain_root != base_domain
                    ):

                        third_party_domains.add(
                            domain
                        )

        # ====================================================
        # CLASSIFY THIRD-PARTY DOMAINS
        # ====================================================

        third_party_categories = {}

        for domain in third_party_domains:

            third_party_categories[
                domain
            ] = classify_third_party(
                domain
            )

        # ====================================================
        # RETURN SCAN RESULTS
        # ====================================================

        return {

            "url": response.url,

            "title": title,

            "https": response.url.startswith(
                "https://"
            ),

            "status_code": response.status_code,

            "scan_status": scan_status,

            "privacy_policy_url": (
                privacy_policy_url
            ),

            "privacy_policy_analysis": (
                privacy_policy_analysis
            ),

            "links": len(links),

            "images": len(images),

            "scripts": len(scripts),

            "forms": len(forms),

            "iframes": len(iframes),

            "cookies": cookie_names,

            "cookie_categories": (
                cookie_categories
            ),

            "third_party_domains": sorted(
                third_party_domains
            ),

            "business_policies": (
                business_policies
            ),

            "third_party_categories": (
                third_party_categories
            )
        }

    except requests.RequestException as e:

        return {

            "error": str(e),

            "scan_status": "error"
        }


# ============================================================
# TEST THE SCANNER
# ============================================================

if __name__ == "__main__":

    website = input(
        "Enter website URL: "
    )

    result = scan_website(
        website
    )

    print(
        "\n--- VeriWeb Scan Result ---"
    )

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )

    privacy_result = calculate_privacy_risk(
        result
    )

    transparency_result = (
        calculate_transparency_score(
            result
        )
    )

    print(
        "\n--- Privacy Risk Assessment ---"
    )

    for key, value in privacy_result.items():

        print(
            f"{key}: {value}"
        )

    print(
        "\n--- Privacy Transparency Assessment ---"
    )

    for key, value in transparency_result.items():

        print(
            f"{key}: {value}"
        )