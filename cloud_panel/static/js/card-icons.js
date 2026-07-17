(function(){
  const rules=[
    [/wireguard|نفق|أنفاق|vpn/i,'◈'],[/راوتر|router|mikrotik/i,'⌁'],
    [/مشترك|subscriber|عميل|client/i,'♙'],[/وكيل|حساب|account|profile|مستخدم/i,'♟'],
    [/صلاح|permission|دخول|login|كلمة المرور/i,'◆'],[/حما|أمان|عزل|security|firewall/i,'⬡'],
    [/إعداد|setting|تهيئة|config/i,'⚙'],[/ترجم|لغة|language|translation/i,'文'],
    [/تحديث|update/i,'↻'],[/سكربت|script|كود|code/i,'</>'],
    [/منفذ|port|تحويل|forward/i,'⇄'],[/خادم|server|نظام|system/i,'▣'],
    [/حالة|status|مراقبة|health/i,'⌁'],[/ملاحظ|note/i,'✎'],
    [/إجراء|action|أمر|command/i,'ϟ'],[/بيانات|معلومات|data|info/i,'i'],
    [/مجموعة|group/i,'⌘'],[/إضافة|تثبيت|إنشاء|add|install|create/i,'＋']
  ];
  function iconFor(text,node){
    const owner=node&&node.closest('[class]');
    const value=(text+' '+(owner?owner.className:'')).toLowerCase();
    const match=rules.find(function(rule){return rule[0].test(value)});
    return match?match[1]:'◇';
  }
  document.querySelectorAll('.panel-head h2,.panel>h2,.panel>h3').forEach(function(title){
    if(title.querySelector('.card-function-icon'))return;
    const icon=document.createElement('span');icon.className='card-function-icon';icon.setAttribute('aria-hidden','true');icon.textContent=iconFor(title.textContent,title);title.prepend(icon);
  });
  document.querySelectorAll('.stat').forEach(function(card){
    if(card.querySelector(':scope > .stat-icon'))return;
    const label=card.querySelector('span');
    const icon=document.createElement('div');icon.className='stat-icon auto-stat-icon';icon.setAttribute('aria-hidden','true');icon.textContent=iconFor(label?label.textContent:'',card);card.prepend(icon);
  });
  document.querySelectorAll('.agent-account-card h3,.permission-account-card h3,.portal-subscriber-card h3,.offline-router-card h3').forEach(function(title){
    if(title.querySelector('.card-function-icon'))return;
    const icon=document.createElement('span');icon.className='card-function-icon small';icon.setAttribute('aria-hidden','true');icon.textContent=iconFor(title.textContent,title);title.prepend(icon);
  });
})();
