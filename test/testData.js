/**
 * Test data for Paranoid Password tests.
 */

// generate domain options
var prefixes = [
  [
    "",
    "http://",
    "https://",
  ],

  [
    "",
    "user@",
    "user:password@"
  ],

  [
    "",
    "subdomain.",
    "multiple.sub.domains."
  ]
];

var domains = [
  "example.com",
  "example.co.uk",
  "somethingwith1numberinit.com",
];

var suffixes = [
  [
    "",
    ":123",
  ],
  [
    "",
    "/path/to/location",
    "/path/to/file.ext"
  ],
  [
    "",
    "?query=thing"
  ],
  [
    "",
    "#anchor"
  ]
];

// generate all the combinations
var testDomains = [];

// :( - forEach in the tightest of loops
prefixes.forEach(function (prefixSection) {
  prefixSection.forEach(function (prefix) {
    domains.forEach(function (domain) {
      suffixes.forEach(function (suffixSection) {
        suffixSection.forEach(function (suffix) {
          var targetDomain = domain;
          if (domain === '') {
            targetDomain = null;
          }
          testDomains.push([
            prefix + domain + suffix,
            targetDomain
          ]);
        });
      });
    });
  });
});
exports.testDomains = testDomains;

exports.randomWords = [
    'exculpated', 'unaging', 'reorganize', 'alexandre', 'estimable',
    'flatlings', 'unsuggestive', 'isatine', 'yannina', 'derider',
    'maslin', 'Bighead', 'undefendable', 'inanely', 'hogshead', 'refine',
    'practised', 'chylous', 'untreasurable', 'spoon', 'pial', 'comstockery',
    'lobscouse', 'hypnotism', 'renavigated', 'Phoebe', 'mott', 'nonsuch',
    'charwoman', 'nongalvanized', 'cabbageworm', 'unamicableness',
    'thoroughfare', 'semidecay', 'exitance', 'historicity', 'groom', 'aetat',
    'corrugate', 'Endothelia', 'kidnaping', 'castellanus', 'dosshouse',
    'sawdust', 'dysthymic', 'massotherapy', 'recirculation', 'xylostromatoid',
    'conceptualizing', 'brackened', 'viz', 'basotho', 'gradable', 'Contactor',
    'misperceiving', 'anthodium', 'courtelle', 'winesap', 'reinvasion',
    'sherris', 'lienable', 'violinistically', 'tongued', 'sinkage',
    'unmendable', 'precompletion', 'autocue', 'Intercoracoid', 'lignitic',
    'preplotting', 'unmutilated', 'bowleggedness', 'chehalis', 'visibility',
    'convulsion', 'overattachment', 'burgess', 'coney', 'everbearing',
    'honeying', 'debt', 'Glyptics', 'nontenurial', 'globefish', 'dowily',
    'handselled', 'hemicrania', 'ponograph', 'unfeminizing', 'ammocete', 'fall',
    'fraileros', 'denaturize', 'foliole', 'edulcorated', 'Posingly',
    'imprudentness', 'cabell', 'jacobine', 'ungyved', 'phenylaceticaldehyde',
    'steatopygy', 'abiotrophy', 'unringing', 'ischia', 'weskit', 'toff',
    'cissaea', 'fruiteries', 'Lindi', 'nicknamed', 'baffle', 'berretta',
    'supersulphuizing', 'graceful', 'eschatologically', 'davenport', 'ferret',
    'hyperexcitement', 'atat', 'otherguess', "dassn't", 'geno', 'Amphogeny',
    'eweries', 'incheon', 'inopportune', 'chandlery', 'vorarlberg',
    'thuddingly', 'sparingness', 'trinidadian', 'subinfeudatory', 'reunitable',
    'lycopod', 'shakhty', 'grandiloquent', 'Palmary', 'collectedness',
    'spearfish', 'forefather', 'leapfrogging', 'scampi', 'underdig',
    'nonscented', 'erective', 'outwitted', 'annotatory', 'subsidiary',
    'moraxella', 'pontianak', 'Tympanitic', 'pothunter', 'coastward',
    'dunsmuir', 'peach', 'folkloristic', 'felinity', 'gargantuan',
    'pseudodiphtherial', 'aluminous', 'opisthognathism', 'commination',
    'yellowlegs', 'laticiferous', 'Innermostly', 'heelpost', 'asuncin',
    'kathodic', 'sizarship', 'backyard', 'augustales', 'fraxinella',
    'episcopise', 'nongenetical', 'nucleolus', 'uxoriously', 'hungeringly',
    'billfish', 'Lateness', 'reinfiltrating', 'sexpartite', 'cyclogenesis',
    'candlewick', 'topheth', 'soundingly', 'gobat', 'unaerated',
    'nonilluminating', 'quodlibetical', 'selectable', 'maltobiose',
    'elegy', 'Stemhead', 'nonowning', 'hennish', 'behalf', 'unforcing',
    'cicely', 'replot', 'hydrobromide', 'vitaliser'
];

exports.testRealDomains = [
    'google.com', 'facebook.com', 'youtube.com', 'yahoo.com', 'baidu.com',
    'wikipedia.org', 'qq.com', 'taobao.com', 'amazon.com', 'live.com'
];

exports.testManualInputs = [
  ["program", "program"],
  ["program name with spaces", "program name with spaces"],
  ["underscores_and-dashes", "underscores_and-dashes"],
  ["1numbers and :things <>", "1numbers and :things <>"],
  ["a weird phrase, with punctuation", "a weird phrase, with punctuation"],
  ["CAPS and LowerCase", "caps and lowercase"],
  ["things. with periods.", "things. with periods."],

  // things that will fail -- :(

  // ["periods.no.spaces.bc.Iliketomakethingshard",
  //   "periods.no.spaces.bc.iliketomakethingshard"]
];

exports.testIPs = [
  ["192.168.1.1", '192.168.1.1'],
  ["http://192.168.1.1", '192.168.1.1'],
  [ "123.23.34.2", "123.23.34.2"],
  ["172.26.168.134","172.26.168.134"],

  ["2001:0000:1234:0000:0000:C1C0:ABCD:0876","2001:0000:1234:0000:0000:c1c0:abcd:0876"],
  ["2001:0:1234::C1C0:ABCD:876","2001:0:1234::c1c0:abcd:876"],
  ["3ffe:0b00:0000:0000:0001:0000:0000:000a","3ffe:0b00:0000:0000:0001:0000:0000:000a"],
  ["3ffe:b00::1:0:0:a","3ffe:b00::1:0:0:a"],
  ["FF02:0000:0000:0000:0000:0000:0000:0001","ff02:0000:0000:0000:0000:0000:0000:0001"],
  ["FF02::1","ff02::1"],
  ["0000:0000:0000:0000:0000:0000:0000:0001","0000:0000:0000:0000:0000:0000:0000:0001"],
  ["0000:0000:0000:0000:0000:0000:0000:0000","0000:0000:0000:0000:0000:0000:0000:0000"],
  ["::","::"],
  ["::ffff:192.168.1.26","::ffff:192.168.1.26"],
  [" 2001:0000:1234:0000:0000:C1C0:ABCD:0876","2001:0000:1234:0000:0000:c1c0:abcd:0876"],
  [" 2001:0:1234::C1C0:ABCD:876","2001:0:1234::c1c0:abcd:876"],
  [" 2001:0000:1234:0000:0000:C1C0:ABCD:0876  ","2001:0000:1234:0000:0000:c1c0:abcd:0876"],
  [" 2001:0:1234::C1C0:ABCD:876  ","2001:0:1234::c1c0:abcd:876"],
  ["2::10","2::10"],
  ["ff02::1","ff02::1"],
  ["fe80::","fe80::"],
  ["2002::","2002::"],
  ["2001:db8::","2001:db8::"],
  ["2001:0db8:1234::","2001:0db8:1234::"],
  ["::ffff:0:0","::ffff:0:0"],
  ["::ffff:192.168.1.1","::ffff:192.168.1.1"],
  ["1:2:3:4:5:6:7:8","1:2:3:4:5:6:7:8"],
  ["1:2:3:4:5:6::8","1:2:3:4:5:6::8"],
  ["1:2:3:4:5::8","1:2:3:4:5::8"],
  ["1:2:3:4::8","1:2:3:4::8"],
  ["1:2:3::8","1:2:3::8"],
  ["1:2::8","1:2::8"],
  ["1::8","1::8"],
  ["1::2:3:4:5:6:7","1::2:3:4:5:6:7"],
  ["1::2:3:4:5:6","1::2:3:4:5:6"],
  ["1::2:3:4:5","1::2:3:4:5"],
  ["1::2:3:4","1::2:3:4"],
  ["1::2:3","1::2:3"],
  ["1::8","1::8"],
  ["::2:3:4:5:6:7:8","::2:3:4:5:6:7:8"],
  ["::2:3:4:5:6:7","::2:3:4:5:6:7"],
  ["::2:3:4:5:6","::2:3:4:5:6"],
  ["::2:3:4:5","::2:3:4:5"],
  ["::2:3:4","::2:3:4"],
  ["::2:3","::2:3"],
  ["::8","::8"],
  ["1:2:3:4:5:6::","1:2:3:4:5:6::"],
  ["1:2:3:4:5::","1:2:3:4:5::"],
  ["1:2:3:4::","1:2:3:4::"],
  ["1:2:3::","1:2:3::"],
  ["1:2::","1:2::"],
  ["1::","1::"],
  ["1:2:3:4:5::7:8","1:2:3:4:5::7:8"],
  ["12345::6:7:8","12345::6:7:8"],
  ["1:2:3:4::7:8","1:2:3:4::7:8"],
  ["1:2:3::7:8","1:2:3::7:8"],
  ["1:2::7:8","1:2::7:8"],
  ["1::7:8","1::7:8"],
  ["fe80::217:f2ff:254.7.237.98","fe80::217:f2ff:254.7.237.98"],
  ["fe80::217:f2ff:fe07:ed62","fe80::217:f2ff:fe07:ed62"],
  ["2001:DB8:0:0:8:800:200C:417A","2001:db8:0:0:8:800:200c:417a"],
  ["FF01:0:0:0:0:0:0:101","ff01:0:0:0:0:0:0:101"],
  ["FF01::101","ff01::101"],
  ["0:0:0:0:0:0:0:1","0:0:0:0:0:0:0:1"],
  ["0:0:0:0:0:0:0:0","0:0:0:0:0:0:0:0"],
  ["2001:2:3:4:5:6:7:134","2001:2:3:4:5:6:7:134"],
  ["fe80::4413:c8ae:2821:5852%10","fe80::4413:c8ae:2821:5852%10"],
];
