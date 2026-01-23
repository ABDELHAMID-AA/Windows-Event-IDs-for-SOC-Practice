

# Event ID 4625 – Failed Logon Report

Hello everyone,

In this report, I'm going to explore **Event ID 4625**. This report will include **two parts**: the first one will cover the information and everything we need to know about this event, and the second one will focus on practicing this event in my own **Splunk lab**.

Let’s proceed step by step.

---

## Event ID 4625 – Failed Logon (Basic Information)

* **Event ID:** 4625
* **Event Name:** An account failed to log on
* **Log Name:** Security
* **Provider:** Microsoft-Windows-Security-Auditing
* **Level:** Information
* **Keywords:** Audit Failure

In simple words:

**4625 is like a hotel failed check-in log.**
It records when someone tries to log in to a Windows computer but fails (wrong password, disabled account, expired account, etc.).

Before diving deeper, let’s clarify **two important things**.

---

## Important Logon Types (Same as 4624)

* **Type 2 – Interactive:** Physical login attempts at the machine.
* **Type 3 – Network:** Failed access to shared resources.
* **Type 10 – RDP:** Failed remote desktop login.

---

## Failure Reasons (Status Codes)

Some common **failure reasons** in 4625 are:

* **0xC000006D:** Wrong username or password
* **0xC000006A:** Bad password
* **0xC0000072:** Account is disabled
* **0xC0000193:** Account expired
* **0xC000006E / 0xC0000070:** Other authentication issues

Knowing these codes helps detect **suspicious patterns**, like repeated bad passwords.

---

## Practice Part

### Brute force detection 

In this practice, I did not try to build something complex. I simply combined Event ID 4624 and Event ID 4625 to create a basic brute force detection and include the source IP address for additional context. Although I worked on a similar idea in the previous report, this time I performed RDP login attempts and used a more personalized SPL query based on my current understanding, and implemented the detection as a Splunk dashboard. The usernames shown in this report are different from the previous one because I changed them during testing, and I also filtered out system and service accounts to reduce noise and focus on real user activity.
**Approach:**

1. Combined **Event ID 4625 (failed logon)** and **Event ID 4624 (successful logon)**.
2. Filtered out **system and service accounts** to focus on real users.
3. Tracked repeated failed attempts and flagged **successful logins that followed multiple failures**, which is a common pattern for brute force attacks.
4. Classified activity as **internal password guessing** or **external online brute force** based on the source IP.

**SPL query used in the dashboard:**

```spl
(EventCode=4625 OR EventCode=4624)
| mvexpand Account_Name
| search NOT (Account_Name IN ("DWM*", "UMFD*", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"))
| where NOT match(Account_Name, "\$$$$")
| sort 0 _time
| streamstats window=80 count(eval(EventCode=4625)) AS failed_count BY Account_Name
| where EventCode=4624 AND failed_count >= 8 AND Logon_Type IN (7,10,2)
| eval possible_bruteforce=if(
     cidrmatch("172.16.0.0/12", Source_Network_Address)
    OR cidrmatch("192.168.0.0/16", Source_Network_Address)
    OR Source_Network_Address="127.0.0.1",
    "password guessing","online bruteforce")
| stats 
    max(failed_count) as failed_attempts 
    by _time Account_Name Source_Network_Address Logon_Type possible_bruteforce
```
![](images/21.png)
**the dashboard:**
![](images/22.png)

**What I learned:**

* How to correlate failed and successful logons to identify suspicious activity.
* How to use `streamstats` to track repeated events over a window of time.
* How to enrich events with `eval` to categorize attacks by source.
* How to build a dashboard that shows patterns instead of individual events, which is closer to real SOC practice.

> This is still just the beginning — I’m exploring more Windows events and refining my detection logic as I go.



