// The demo copy's suggested fixes: one fixed answer per kind of risk, written with AI and checked by the team before
// the demo, so the demo never shows an answer nobody has read. The real console shows the core's own fix instead.
// Plain words for a business owner: the action first (never the IP address again: it is in What happened), then why.
export const DEMO_FIXES: Record<string, string> = {
  privilege_escalation:
    'SentrAI already stopped the program it started and blocked the IP address mentioned above for 2 hours, so that ' +
    'they cannot use it to take over the machine. Keep the block. The SentrAI team will check this machine with you.',
  data_exfiltration:
    'SentrAI already blocked the IP address mentioned above for 2 hours, so that they cannot take any more customer ' +
    'data while you check. Keep the block. Only bait records were read, so no real customer data was taken.',
  brute_force:
    'SentrAI already blocked the IP address mentioned above and slowed down sign-ins for 2 hours, so that they cannot ' +
    'keep guessing passwords. Keep the block, and ask the account owner to change their password.',
  sql_injection:
    'SentrAI already blocked the IP address mentioned above for 2 hours and switched on a website filter for this ' +
    'trick, so that they cannot try again while your website is checked. Keep the block.',
  xss:
    'Block the IP address mentioned above for 2 hours, so that they cannot try to plant code on your website again.',
  port_scan:
    'Block the IP address mentioned above for 2 hours, so that they cannot come back through a way in they may have ' +
    'found. Press "Do the suggested fix" to block it, or "Not a threat" if it is a check you asked for.',
  staff_report:
    'Tell your staff not to click the link, and delete the email. If anyone already typed their password there, ' +
    'change it now. Press "Ask the SentrAI team" and they will check that nothing else was affected.',
  misconfiguration:
    'Press "Ask the SentrAI team" and they will close the open setting for you.',
  log_tampering:
    'SentrAI kept its own copy of the records, so nothing is lost. Press "Ask the SentrAI team" and they will find ' +
    'out who changed them and make the machine safe again.',
  prompt_injection:
    'Block the IP address mentioned above for 2 hours, so that they cannot try again. The attack was caught anyway.',
  malware:
    'Do not open the file. Press "Ask the SentrAI team" and they will remove it and check the machine.',
  unauthorised_admin:
    'If it was you or your team, press "This was me". If not, keep the block, so that they cannot use the machine, ' +
    'and the SentrAI team will check it.',
}
