import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


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

def calculate_privacy_risk(scan_result):
    
    score = 0
    reasons = []

    # HTTPS check
    if not scan_result["https"]:
        score += 30
        reasons.append("Website does not use HTTPS.")

    # Cookie analysis
    cookie_categories = scan_result["cookie_categories"]

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
        score += unknown_count * 1
        reasons.append(
            f"{unknown_count} cookie(s) could not be classified."
        )

    # Third-party services
    third_party_categories = scan_result["third_party_categories"]

    advertising_services = 0
    analytics_services = 0

    for category in third_party_categories.values():

        if category == "advertising":
            advertising_services += 1

        elif category == "analytics":
            analytics_services += 1

    if analytics_services > 0:
        score += analytics_services * 5
        reasons.append(
            f"{analytics_services} analytics service(s) detected."
        )

    if advertising_services > 0:
        score += advertising_services * 10
        reasons.append(
            f"{advertising_services} advertising service(s) detected."
        )

    # Limit score to 100
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

def scan_website(url):

    # Make sure the URL has a protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        # Analyze cookies
        cookies = response.cookies

        cookie_names = []
        cookie_categories = {}

        for cookie in cookies:
            cookie_names.append(cookie.name)
            cookie_categories[cookie.name] = classify_cookie(cookie.name)

        # Parse HTML
        soup = BeautifulSoup(response.text, "html.parser")

        # Get website domain
        parsed_url = urlparse(response.url)
        base_domain = parsed_url.netloc

        # Website title
        title = (
            soup.title.string.strip()
            if soup.title and soup.title.string
            else "No title"
        )

        # Basic HTML elements
        links = soup.find_all("a")
        images = soup.find_all("img")
        scripts = soup.find_all("script")
        forms = soup.find_all("form")
        iframes = soup.find_all("iframe")

        # Find third-party resources
        third_party_domains = set()

        # Check links
        for link in links:

            href = link.get("href")

            if href and href.startswith(("http://", "https://")):

                domain = urlparse(href).netloc

                if domain and domain != base_domain:
                    third_party_domains.add(domain)

        # Check scripts
        for script in scripts:

            src = script.get("src")

            if src and src.startswith(("http://", "https://")):

                domain = urlparse(src).netloc

                if domain and domain != base_domain:
                    third_party_domains.add(domain)

        # Check images
        for image in images:

            src = image.get("src")

            if src and src.startswith(("http://", "https://")):

                domain = urlparse(src).netloc

                if domain and domain != base_domain:
                    third_party_domains.add(domain)

        # Check iframes
        for iframe in iframes:

            src = iframe.get("src")

            if src and src.startswith(("http://", "https://")):

                domain = urlparse(src).netloc

                if domain and domain != base_domain:
                    third_party_domains.add(domain)

        # Classify third-party domains
        third_party_categories = {}

        for domain in third_party_domains:
            third_party_categories[domain] = classify_third_party(domain)

        # Return scan results
        return {
            "url": response.url,
            "title": title,
            "https": response.url.startswith("https://"),
            "status_code": response.status_code,
            "links": len(links),
            "images": len(images),
            "scripts": len(scripts),
            "forms": len(forms),
            "iframes": len(iframes),
            "cookies": cookie_names,
            "cookie_categories": cookie_categories,
            "third_party_domains": sorted(third_party_domains),
            "third_party_categories": third_party_categories
        }

    except requests.RequestException as e:

        return {
            "error": str(e)
        }


# Test the scanner
if __name__ == "__main__":

    website = input("Enter website URL: ")

    result = scan_website(website)

print("\n--- VeriWeb Scan Result ---")

for key, value in result.items():
    print(f"{key}: {value}")

privacy_result = calculate_privacy_risk(result)

print("\n--- Privacy Risk Assessment ---")

for key, value in privacy_result.items():
    print(f"{key}: {value}")