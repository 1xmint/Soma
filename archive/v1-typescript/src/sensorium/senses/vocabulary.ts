/**
 * Sense 1: Vocabulary Fingerprint
 *
 * Measures the statistical distribution of word choices — not WHAT the agent
 * says but the probabilistic shape of HOW it says it. Every model has
 * characteristic vocabulary preferences baked in by training, like recognizing
 * someone's accent.
 */

// --- Types ---

export interface VocabularySignals {
  vocabTypeTokenRatio: number;
  vocabHapaxRatio: number;
  vocabAvgWordFrequencyRank: number;
  vocabTopBigramsHash: number;
  vocabSentenceStarterEntropy: number;
  vocabFillerPhraseCount: number;
  vocabContractionRatio: number;
  vocabPassiveVoiceRatio: number;
  vocabQuestionDensity: number;
  vocabModalVerbRatio: number;
}

// --- Top 5000 English words by frequency (rank map) ---
// Subset of the most common English words. Words not in this list get rank 5001.

const TOP_WORDS: string[] = [
  "the","be","to","of","and","a","in","that","have","i","it","for","not","on","with",
  "he","as","you","do","at","this","but","his","by","from","they","we","her","she","or",
  "an","will","my","one","all","would","there","their","what","so","up","out","if","about",
  "who","get","which","go","me","when","make","can","like","time","no","just","him","know",
  "take","people","into","year","your","good","some","could","them","see","other","than",
  "then","now","look","only","come","its","over","think","also","back","after","use","two",
  "how","our","work","first","well","way","even","new","want","because","any","these","give",
  "day","most","us","great","between","need","large","often","those","turn","long","very",
  "small","hand","high","help","line","before","much","right","too","mean","old","each",
  "tell","does","set","three","own","point","end","why","ask","men","went","find","here",
  "thing","many","let","begin","seem","country","head","still","last","read","keep","never",
  "start","life","run","while","number","might","next","open","state","own","place","live",
  "where","school","become","real","part","off","every","move","show","try","same","another",
  "should","call","world","house","home","water","room","write","down","still","may","big",
  "group","lead","stand","change","study","few","night","always","play","name","put","thought",
  "say","must","kind","leave","child","city","talk","case","woman","seem","fact","until",
  "problem","close","feel","quite","already","walk","story","late","during","door","side",
  "area","since","power","boy","face","young","yet","system","ago","follow","company","come",
  "under","around","enough","question","bring","word","family","form","light","develop","hold",
  "govern","possible","far","early","example","program","ever","both","without","eye","less",
  "hear","grow","body","result","open","course","second","week","member","pay","offer","until",
  "car","important","present","several","nothing","sure","something","include","social",
  "provide","service","however","political","human","believe","million","per","student","hand",
  "report","age","among","level","allow","add","office","spend","health","person","art","war",
  "history","party","within","low","able","suggest","month","music","mother","figure","father",
  "plan","sit","continue","increase","market","interest","industry","voice","different","view",
  "direction","community","once","class","law","whole","above","meet","job","table","court",
  "produce","teach","education","american","rate","local","process","cut","involve","effort",
  "matter","special","across","often","act","practice","simple","south","usually","love",
  "consider","bit","piece","remember","north","issue","center","west","order","business",
  "expect","clear","today","team","moment","stop","wait","better","general","build","data",
  "model","rest","minute","note","hope","research","common","food","town","letter","deal",
  "land","drive","test","record","bank","window","return","city","street","paper","condition",
  "reason","free","cost","perhaps","control","effect","policy","pass","watch","though","mind",
  "experience","national","field","force","fish","sense","security","street","action","sign",
  "require","death","perhaps","public","rule","instead","speak","nature","white","press",
  "information","least","product","position","step","answer","choose","season","mark","black",
  "ground","support","attention","late","game","decision","morning","approach","material",
  "role","amount","economic","ready","player","agree","price","total","happy","likely","short",
  "church","language","image","fire","doctor","similar","receive","size","base","single",
  "actually","along","among","hit","cover","event","appear","region","evidence","manager",
  "enjoy","indeed","various","whether","cold","risk","period","contain","defense","list",
  "quality","carry","loss","performance","value","fight","training","project","reach","star",
  "popular","protect","trade","election","design","choice","knowledge","sort","reduce","past",
  "account","explain","accept","natural","challenge","remain","statement","staff","nearly",
  "traditional","detail","outside","modern","final","major","technology","culture","fund",
  "director","response","significant","resource","central","claim","task","scene","movement",
  "financial","represent","range","relate","either","press","standard","message","announce",
  "effort","draw","determine","measure","specific","strategy","pattern","behavior","share",
  "weight","apply","energy","wide","structure","create","environment","focus","describe",
  "opportunity","establish","wall","character","treatment","avoid","identify","manage","factor",
  "operation","generation","section","cause","concern","approach","compare","theory","imagine",
  "type","occur","benefit","indicate","attack","capital","reflect","media","argue","current",
  "article","personal","enter","serious","despite","suggest","discussion","physical","store",
  "feature","skill","analysis","medical","responsibility","expert","firm","reveal","exist",
  "tend","impact","particularly","purpose","address","institution","remove","debate","mention",
  "remain","reality","serve","hard","difference","recognize","prepare","executive","simply",
  "source","observe","successful","citizen","wonder","affect","raise","audience","oil","entire",
  "century","feeling","vote","artist","animal","century","democratic","degree","emerge","edge",
  "shoulder","bag","speech","access","stock","network","participant","push","property","prevent",
  "collection","reference","campaign","quickly","dark","surface","charge","seek","consumer",
  "stage","green","hang","administration","release","publish","shoot","commission","key",
  "blue","beautiful","consider","assume","agent","style","executive","tough","join","trouble",
  "deep","save","series","maintain","element","smile","shake","fly","apply","garden","gas",
  "demand","threat","beat","success","throw","miss","cultural","memory","former","race","box",
  "dream","official","shoulder","professional","admit","civil","leg","define","discover",
  "trial","pull","drop","fill","violence","weapon","machine","income","struggle","crime",
  "religion","ahead","peace","skin","status","decade","behavior","finish","option","movement",
  "labor","critical","communication","season","sit","technology","protect","congress","hotel",
  "chair","lay","production","partner","brother","trip","sister","feeling","pain","knowledge",
  "afraid","female","teach","tiny","arrive","fit","tonight","clean","rain","cold","wind",
  "cry","finger","lunch","spread","spring","nurse","tooth","cup","safe","native","immediately",
  "spot","surprise","wood","obviously","lack","engage","mile","refuse","reform","promise",
  "quiet","investigate","crowd","horse","bus","clothes","soft","sign","solution","wonderful",
  "bottom","mistake","basic","cool","hill","count","progress","sleep","terrible","connection",
  "nose","perfect","limit","survive","ride","exchange","supply","grab","complex","somewhat",
  "initial","regular","nor","assessment","capable","primary","afraid","confirm","corner",
  "independent","smooth","equally","settle","cash","youth","potential","category","shift",
  "opposition","internal","judge","panel","expand","collect","kitchen","master","opinion",
  "objective","liberal","normally","rural","plenty","display","taste","acquire","frame","manner",
  "birth","conflict","opposition","perspective","debate","length","vast","commit","tiny",
  "household","strongly","minority","notion","average","extend","victory","disappear","strike",
  "honor","increasingly","device","recall","wage","secure","broad","outcome","brief","hide",
  "assumption","perfectly","visible","criticism","tone","conversation","narrow","straight",
  "familiar","regulation","cream","convince","mixture","anger","retire","resistance","favor",
  "launch","typical","chapter","overall","abandon","tradition","negotiate","urban","usual",
  "criticism","revenue","ethnic","estimate","extraordinary","operate","arise","nose","slightly",
  "shift","increasingly","liberal","accident","diet","impose","constitutional","normally",
  "examine","contrast","approve","arrange","struggle","variable","propose","supreme","emerge",
  "priority","careful","willing","recognition","apparent","legislation","pollution","sensitive",
  "extensive","emotion","generate","wrap","compete","afford","recover","joint","intellectual",
  "convince","inevitable","prayer","ultimately","mission","territory","aid","crisis","theme",
  "classroom","meanwhile","permanent","consequence","sufficient","modify","resolve","terrorist",
  "initiative","climate","passenger","aggressive","dramatic","peak","appeal","slowly","raw",
  "fundamental","exposure","scared","capability","restriction","deny","false","nerve","curious",
  "fiber","researcher","concentrate","panel","pollution","dramatic","resistance","convince",
  "transition","eliminate","barely","constantly","injury","demonstrate","link","ethnic","urban",
  "legitimate","accomplish","contemporary","fortune","cluster","distinction","literary","swear",
  "impression","framework","principal","assault","fiction","intense","compromise","attract",
  "loud","construct","perspective","valid","embrace","portrait","essence","virtue","formula",
  "fate","stimulus","enthusiasm","incorporate","evolve","ideology","yield","compose","mere",
  "venture","narrative","sustain","aesthetic","advocate","craft","gravity","precise","bias",
  "pose","tolerance","portfolio","innovation","deficit","transparent","genuine","ambition",
  "horizon","mobility","curiosity","harsh","interfere","rigid","integrity","trait","illusion",
  "distort","irony","privilege","spectrum","implicit","dense","confront","empirical","profound",
  "dimension","subtle","nurture","coherent","anticipate","articulate","dilemma","paradigm",
  "align","momentum","rhetoric","vulnerability","surplus","perception","complement","resilience",
  "aggregate","amid","arbitrary","contextual","discrepancy","elaborate","feasible","hierarchy",
  "inherent","juxtapose","leverage","nuance","optimize","pragmatic","reconcile","scrutiny",
  "threshold","undermine","viable","warrant","abstraction","benchmark","calibrate","diverge",
  "encompass","fluctuate","granular","holistic","iterate","mitigate","nomenclature","overhead",
  "parameter","quantify","replicate","scalable","tangible","unprecedented","velocity","workflow"
];

const WORD_RANK_MAP = new Map<string, number>();
for (let i = 0; i < TOP_WORDS.length; i++) {
  const word = TOP_WORDS[i];
  if (!WORD_RANK_MAP.has(word)) {
    WORD_RANK_MAP.set(word, i + 1);
  }
}
const DEFAULT_RANK = TOP_WORDS.length + 1;

// --- Filler phrases ---

const FILLER_PHRASES = [
  "however", "moreover", "additionally", "in addition", "furthermore",
  "it's worth noting", "that being said", "on the other hand",
  "in other words", "as mentioned",
];

// --- Contraction patterns ---

const CONTRACTION_RE = /\b(?:i'm|i've|i'll|i'd|he's|she's|it's|we're|we've|we'll|we'd|they're|they've|they'll|they'd|you're|you've|you'll|you'd|isn't|aren't|wasn't|weren't|don't|doesn't|didn't|won't|wouldn't|can't|couldn't|shouldn't|haven't|hasn't|hadn't|mustn't|let's|that's|who's|what's|where's|there's|here's|how's|ain't)\b/gi;

// --- Modal verbs ---

const MODAL_VERBS = new Set(["could", "would", "should", "might", "may", "can", "will", "shall", "must"]);

// --- Passive voice detection ---
// Pattern: "was/were/is/are/been/be/being" + optional adverb + past participle (ending in "ed" or "en", or common irregular forms)

const PASSIVE_AUX_RE = /\b(?:was|were|is|are|been|be|being)\s+(?:\w+ly\s+)?(\w+(?:ed|en|wn|nt|pt|lt|ft|ght|ung|uck|orn|ade|one|oken|osen|oven|iven|tten|dden))\b/gi;

// --- Helpers ---

function tokenize(text: string): string[] {
  return text.toLowerCase().replace(/[^\w\s''-]/g, " ").split(/\s+/).filter(w => w.length > 0);
}

function splitSentences(text: string): string[] {
  return text.split(/[.!?]+/).map(s => s.trim()).filter(s => s.length > 0);
}

function shannonEntropy(items: string[]): number {
  if (items.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const item of items) {
    counts.set(item, (counts.get(item) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / items.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Simple numeric hash of a sorted bigram list into a fingerprint. */
function hashBigrams(bigrams: string[]): number {
  let hash = 0;
  for (const bigram of bigrams) {
    for (let i = 0; i < bigram.length; i++) {
      hash = ((hash << 5) - hash + bigram.charCodeAt(i)) | 0;
    }
  }
  // Normalize to a positive number in a reasonable range
  return Math.abs(hash) % 1000000;
}

// --- Main Extractor ---

export function extractVocabularySignals(text: string): VocabularySignals {
  const words = tokenize(text);
  const totalWords = words.length;

  if (totalWords === 0) {
    return {
      vocabTypeTokenRatio: 0,
      vocabHapaxRatio: 0,
      vocabAvgWordFrequencyRank: 0,
      vocabTopBigramsHash: 0,
      vocabSentenceStarterEntropy: 0,
      vocabFillerPhraseCount: 0,
      vocabContractionRatio: 0,
      vocabPassiveVoiceRatio: 0,
      vocabQuestionDensity: 0,
      vocabModalVerbRatio: 0,
    };
  }

  // --- Type-Token Ratio ---
  const wordFreqs = new Map<string, number>();
  for (const w of words) {
    wordFreqs.set(w, (wordFreqs.get(w) ?? 0) + 1);
  }
  const uniqueWords = wordFreqs.size;
  const vocabTypeTokenRatio = uniqueWords / totalWords;

  // --- Hapax Ratio ---
  let hapaxCount = 0;
  for (const count of wordFreqs.values()) {
    if (count === 1) hapaxCount++;
  }
  const vocabHapaxRatio = uniqueWords === 0 ? 0 : hapaxCount / uniqueWords;

  // --- Average Word Frequency Rank ---
  let totalRank = 0;
  for (const w of words) {
    totalRank += WORD_RANK_MAP.get(w) ?? DEFAULT_RANK;
  }
  const vocabAvgWordFrequencyRank = totalRank / totalWords;

  // --- Top Bigrams Hash ---
  const bigramCounts = new Map<string, number>();
  for (let i = 0; i < words.length - 1; i++) {
    const bigram = `${words[i]} ${words[i + 1]}`;
    bigramCounts.set(bigram, (bigramCounts.get(bigram) ?? 0) + 1);
  }
  const sortedBigrams = [...bigramCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([bg]) => bg)
    .sort(); // alphabetical sort for determinism
  const vocabTopBigramsHash = hashBigrams(sortedBigrams);

  // --- Sentence Starter Entropy ---
  const sentences = splitSentences(text);
  const starters = sentences
    .map(s => {
      const firstWord = s.trim().split(/\s+/)[0];
      return firstWord ? firstWord.toLowerCase().replace(/[^\w]/g, "") : "";
    })
    .filter(w => w.length > 0);
  const vocabSentenceStarterEntropy = shannonEntropy(starters);

  // --- Filler Phrase Count ---
  const lowerText = text.toLowerCase();
  let vocabFillerPhraseCount = 0;
  for (const filler of FILLER_PHRASES) {
    let searchFrom = 0;
    while (true) {
      const idx = lowerText.indexOf(filler, searchFrom);
      if (idx === -1) break;
      vocabFillerPhraseCount++;
      searchFrom = idx + filler.length;
    }
  }

  // --- Contraction Ratio ---
  const contractionMatches = text.match(CONTRACTION_RE);
  const contractionCount = contractionMatches ? contractionMatches.length : 0;
  const vocabContractionRatio = contractionCount / totalWords;

  // --- Passive Voice Ratio ---
  let passiveCount = 0;
  for (const sentence of sentences) {
    if (PASSIVE_AUX_RE.test(sentence)) {
      passiveCount++;
    }
    // Reset lastIndex since we're using global flag
    PASSIVE_AUX_RE.lastIndex = 0;
  }
  const vocabPassiveVoiceRatio = sentences.length === 0 ? 0 : passiveCount / sentences.length;

  // --- Question Density ---
  const questionCount = (text.match(/\?/g) || []).length;
  const vocabQuestionDensity = (questionCount / totalWords) * 100;

  // --- Modal Verb Ratio ---
  let modalCount = 0;
  for (const w of words) {
    if (MODAL_VERBS.has(w)) modalCount++;
  }
  const vocabModalVerbRatio = modalCount / totalWords;

  return {
    vocabTypeTokenRatio,
    vocabHapaxRatio,
    vocabAvgWordFrequencyRank,
    vocabTopBigramsHash,
    vocabSentenceStarterEntropy,
    vocabFillerPhraseCount,
    vocabContractionRatio,
    vocabPassiveVoiceRatio,
    vocabQuestionDensity,
    vocabModalVerbRatio,
  };
}

/** Feature names for the vocabulary sense, matching the order in the signal object. */
export const VOCABULARY_FEATURE_NAMES: string[] = [
  "vocab_type_token_ratio",
  "vocab_hapax_ratio",
  "vocab_avg_word_frequency_rank",
  "vocab_top_bigrams_hash",
  "vocab_sentence_starter_entropy",
  "vocab_filler_phrase_count",
  "vocab_contraction_ratio",
  "vocab_passive_voice_ratio",
  "vocab_question_density",
  "vocab_modal_verb_ratio",
];

/** Convert vocabulary signals to a numeric feature vector. */
export function vocabularyToFeatureVector(signals: VocabularySignals): number[] {
  return [
    signals.vocabTypeTokenRatio,
    signals.vocabHapaxRatio,
    signals.vocabAvgWordFrequencyRank,
    signals.vocabTopBigramsHash,
    signals.vocabSentenceStarterEntropy,
    signals.vocabFillerPhraseCount,
    signals.vocabContractionRatio,
    signals.vocabPassiveVoiceRatio,
    signals.vocabQuestionDensity,
    signals.vocabModalVerbRatio,
  ];
}
