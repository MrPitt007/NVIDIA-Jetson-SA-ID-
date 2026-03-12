import requests, time
BASE = "http://127.0.0.1:8001"
print("=" * 50)
print("SA-ID BACKEND - AUTO TEST SUITE")
print("=" * 50)
results = []
print("\n[1] Health Ping...")
try:
    r = requests.get(BASE+"/api/v1/health/ping",timeout=5)
    print("    PASS" if r.status_code==200 else "    FAIL"); results.append(r.status_code==200)
except: print("    FAIL - server not running!"); results.append(False)
print("\n[2] Get Token...")
token=None
try:
    r = requests.post(BASE+"/api/v1/auth/token",timeout=5,json={"terminal_id":"T001","merchant_id":"M001","client_type":"BANK","api_key":"test-api-key-minimum-32-chars-here"})
    token=r.json()["access_token"]; print("    PASS token="+token[:30]+"..."); results.append(True)
except Exception as e: print("    FAIL",e); results.append(False)
print("\n[3] Verify valid ID...")
try:
    r = requests.post(BASE+"/api/v1/identity/verify",timeout=5,headers={"Authorization":"Bearer "+token},json={"id_number":"2909315800085","surname":"DLAMINI","given_names":"SIPHO","dob":"19900101","terminal_id":"T001"})
    d=r.json(); print("    PASS verified="+str(d["verified"])+" score="+str(d["bio_score"])); results.append(d["verified"])
except Exception as e: print("    FAIL",e); results.append(False)
print("\n[4] Block R10000 no biometric...")
try:
    r = requests.post(BASE+"/api/v1/payment/initiate",timeout=5,headers={"Authorization":"Bearer "+token},json={"amount_zar":10000,"method":"chip","merchant_id":"M001","terminal_id":"T001","id_number":"2909315800085","id_verified":False})
    print("    PASS blocked!" if r.status_code==403 else "    FAIL"); results.append(r.status_code==403)
except Exception as e: print("    FAIL",e); results.append(False)
print("\n"+"="*50)
print(f"  {sum(results)}/{len(results)} TESTS PASSED")
print("="*50)
