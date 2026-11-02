// The demo copy's suggested fixes: one fixed answer per kind of risk, written with AI and checked by the team before
// the demo, so the demo never shows an answer nobody has read. The real console shows the core's own fix instead.
// Plain words for a business owner: what to do, and what SentrAI already did.
export const DEMO_FIXES: Record<string, string> = {
  privilege_escalation:
    'SentrAI has already cut this address off and stopped the program it started. Keep the block, and ask your ' +
    'technical staff to check this machine today. Leave it switched on so the evidence stays, and change the ' +
    'passwords used on it once it has been checked.',
  data_exfiltration:
    'This address opened bait records that no real customer can reach, so it is not a customer. SentrAI has already ' +
    'blocked it. Keep the block. Nothing real was taken, because only bait data was read.',
  brute_force:
    'SentrAI has already blocked the address that kept guessing and slowed down the sign-in page. Keep the block, and ' +
    'ask the owner of the account to change their password and turn on two-step sign-in.',
  sql_injection:
    'SentrAI has already blocked this address and added a filter that stops this trick on your website. Keep the ' +
    'block. When you can, ask your web developer to check the page that was targeted.',
  xss:
    'SentrAI has blocked this address. Keep the block, and ask your web developer to check the page that was ' +
    'targeted so it cannot show code to your visitors.',
  port_scan:
    'Someone was looking around for a way in, and nothing got through. Blocking the address is a safe step: press ' +
    '"Do the suggested fix" to block it, or "Not a threat" if it is a scan you asked for.',
  staff_report:
    'A member of staff saw an email asking them to re-enter their password on a strange link. Tell your staff not to ' +
    'click it, and delete the email. If anyone already typed their password there, change it now. Press "Not a ' +
    'threat" when everyone has been told.',
  misconfiguration:
    'A setting on this machine is left open. Ask your technical staff to close it, then press "Not a threat" to clear ' +
    'this card.',
  log_tampering:
    'Someone tried to change the record of what happened. SentrAI kept its own copy, so nothing is lost. Keep any ' +
    'block in place, and ask your technical staff to check who had access to this machine.',
  prompt_injection:
    "Someone tried to trick SentrAI's AI into ignoring an attack. It did not work: the attack was caught anyway. Keep " +
    'the block.',
  malware:
    'A harmful file was found. Do not open it. Ask your technical staff to remove it and check the machine.',
  unauthorised_admin:
    'Someone used the full (root) access on this machine from a sign-in SentrAI does not know. If it was you or your ' +
    'team, press "This was me". If not, keep the block and call your technical staff now.',
}
