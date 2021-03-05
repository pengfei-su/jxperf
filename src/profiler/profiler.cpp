#include <assert.h>
#include <errno.h>
#include <dlfcn.h>
#include <algorithm>
#include <iomanip> 
#include <stack>
#include <cmath>
#include <iostream>
#include "config.h"
#include "context.h"
#include "profiler.h"
#include "thread_data.h"
#include "perf_interface.h"
#include "stacktraces.h"
#include "agent.h"
#include "metrics.h"
#include "debug.h"
#include "x86-misc.h"
#include "context-pc.h" 
#include "safe-sampling.h"
#include "welford.h"

#define APPROX_RATE (0.01)
#define MAX_FRAME_NUM (128)
#define MAX_IP_DIFF (100000000)

Profiler Profiler::_instance;
ASGCT_FN Profiler::_asgct = nullptr;
std::string clientName;

static SpinLock lock_map;
static std::unordered_map<Context*, Context*> map = {};

uint64_t GCCounter = 0;
// thread_local uint64_t localGCCounter = 0;

static SpinLock sk;

uint64_t grandTotGenericCounter = 0;
thread_local uint64_t totalGenericCounter = 0;

thread_local void *prevIP = (void *)0;

namespace {

Context *constructContext(ASGCT_FN asgct, void *uCtxt, uint64_t ip, jmethodID method_id, uint32_t method_version, ContextFrame *callee_ctxt_frame) {
    ContextTree *ctxt_tree = reinterpret_cast<ContextTree *> (TD_GET(context_state));
    Context *last_ctxt = nullptr;

    ASGCT_CallFrame frames[MAX_FRAME_NUM];
    ASGCT_CallTrace trace;
    trace.frames = frames;
    trace.env_id = JVM::jni();
    asgct(&trace, MAX_FRAME_NUM, uCtxt); 

    for (int i = trace.num_frames - 1 ; i >= 1; i--) {
        // TODO: We need to consider how to include the native method.
        ContextFrame ctxt_frame;
        if (i == 0) {
            ctxt_frame.binary_addr = ip;
        }
        ctxt_frame = frames[i]; //set method_id and bci
        if (last_ctxt == nullptr) last_ctxt = ctxt_tree->addContext((uint32_t)CONTEXT_TREE_ROOT_ID, ctxt_frame);
        else last_ctxt = ctxt_tree->addContext(last_ctxt, ctxt_frame);
    }

    // leaf node 
    ContextFrame ctxt_frame;
    ctxt_frame.binary_addr = ip;
    ctxt_frame.method_id = method_id;
    ctxt_frame.method_version = method_version;
    if (last_ctxt != nullptr) last_ctxt = ctxt_tree->addContext(last_ctxt, ctxt_frame);
    else last_ctxt = ctxt_tree->addContext((uint32_t)CONTEXT_TREE_ROOT_ID, ctxt_frame);
    
    // the first instruction in the Callee
    last_ctxt = ctxt_tree->addContext(last_ctxt, *callee_ctxt_frame);
    // delete callee_ctxt_frame; 
    
    return last_ctxt;
}

}

#define MAX_STACK 64                                                                              
#define MAX_EVENTS 5

typedef struct EventValueStack {                                                                   
    int top;                                                                                       
    uint64_t value[MAX_STACK][MAX_EVENTS];                                                         
} CPUEventStack_t;

thread_local int curEventId = 0;
thread_local int eventFd[MAX_EVENTS];

void SetupEventFd(int fd) {
    eventFd[curEventId++] = fd;
}

int curWatermarkId = 0;
int sample_cnt_metric_id = -1;
// int pebs_metric_id[MAX_EVENTS];
int mean_metric_id[MAX_EVENTS];
int variance_metric_id[MAX_EVENTS];
int m2_metric_id[MAX_EVENTS];
int cv_metric_id[MAX_EVENTS];

void SetupWatermarkMetric(std::string client_name, std::string event_name, int event_threshold) {
    if (curWatermarkId == MAX_EVENTS) {
        ERROR("curWatermarkId == MAX_EVENTS = %d", MAX_EVENTS);
        assert(false);
    }
   
    // pebs_metric_id[curWatermarkId] = metricId;
    if (curWatermarkId == 0) {
        metrics::metric_info_t metric_sample_cnt_info;
        metric_sample_cnt_info.client_name = client_name;
        metric_sample_cnt_info.event_name = event_name;
        metric_sample_cnt_info.event_measure = "COUNT";
        metric_sample_cnt_info.threshold = event_threshold;
        metric_sample_cnt_info.val_type = metrics::METRIC_VAL_INT;
        sample_cnt_metric_id = metrics::MetricInfoManager::registerMetric(metric_sample_cnt_info);
    } else {
        metrics::metric_info_t metric_mean_info;
        metric_mean_info.client_name = client_name;
        metric_mean_info.event_name = event_name;
        metric_mean_info.event_measure = "MEAN";
        metric_mean_info.threshold = event_threshold;
        metric_mean_info.val_type = metrics::METRIC_VAL_REAL;
        mean_metric_id[curWatermarkId] = metrics::MetricInfoManager::registerMetric(metric_mean_info);
        
        metrics::metric_info_t metric_variance_info;
        metric_variance_info.client_name = client_name;
        metric_variance_info.event_name = event_name;
        metric_variance_info.event_measure = "VARIANCE";
        metric_variance_info.threshold = event_threshold;
        metric_variance_info.val_type = metrics::METRIC_VAL_REAL;
        variance_metric_id[curWatermarkId] = metrics::MetricInfoManager::registerMetric(metric_variance_info);
	
        metrics::metric_info_t metric_m2_info;
        metric_m2_info.client_name = client_name;
        metric_m2_info.event_name = event_name;
        metric_m2_info.event_measure = "M2";
        metric_m2_info.threshold = event_threshold;
        metric_m2_info.val_type = metrics::METRIC_VAL_REAL;
        m2_metric_id[curWatermarkId] = metrics::MetricInfoManager::registerMetric(metric_m2_info);
	
        metrics::metric_info_t metric_cv_info;
        metric_cv_info.client_name = client_name;
        metric_cv_info.event_name = event_name;
        metric_cv_info.event_measure = "CV";
        metric_cv_info.threshold = event_threshold;
        metric_cv_info.val_type = metrics::METRIC_VAL_REAL;
        cv_metric_id[curWatermarkId] = metrics::MetricInfoManager::registerMetric(metric_cv_info);
    }

    curWatermarkId++;
}


thread_local CPUEventStack_t CPUEventStack = {.top = -1}; 

void Profiler::OnSample(int eventID, perf_sample_data_t *sampleData, void *uCtxt) {
    
    void *sampleIP = (void *)(sampleData->ip);
    void *stackAddr = (void **)getContextSP(uCtxt);
    if (!IsValidAddress(sampleIP, stackAddr)) return;
    
    jmethodID method_id = 0;
    uint32_t method_version = 0;
    CodeCacheManager &code_cache_manager = Profiler::getProfiler().getCodeCacheManager();
    
    CompiledMethod *method = code_cache_manager.getMethod(sampleData->ip, method_id, method_version);
    if (method == nullptr) return;

#ifdef PRINT_SAMPLED_INS
     std::ofstream *pmu_ins_output_stream = reinterpret_cast<std::ofstream *>(TD_GET(pmu_ins_output_stream));
     assert(pmu_ins_output_stream != nullptr); 
     print_single_instruction(pmu_ins_output_stream, (const void *)sampleIP);
#endif
    
   // uint32_t threshold = (metrics::MetricInfoManager::getMetricInfo(metric_id1))->threshold;

   // Context *watchCtxt = constructContext(_asgct, uCtxt, sampleData->ip, nullptr, method_id, method_version);
   // if (watchCtxt == nullptr) return;
    
    int top = ++CPUEventStack.top;
    assert(curEventId >= 1);
    for (int i = 1; i < curEventId; i++) {
    	assert(read(eventFd[i], &(CPUEventStack.value[top][i]), sizeof(uint64_t)) > 0);
    }
    /* 
    metrics::ContextMetrics *metrics = watchCtxt->getMetrics();
    if (metrics == nullptr) {
        metrics = new metrics::ContextMetrics();
        watchCtxt->setMetrics(metrics); 
    }
    metrics::metric_val_t metric_val;
    metric_val.i = 1;
    assert(metrics->increment(sample_cnt_metric_id, metric_val));
    */
    ContextFrame *callee_ctxt_frame = new ContextFrame;
    callee_ctxt_frame->binary_addr = (uint64_t)sampleIP;
    callee_ctxt_frame->method_id = method_id;
    callee_ctxt_frame->method_version = method_version;
    
    SampleData_t sd= {
         .va = stackAddr,
         .watchLen = sizeof(uint64_t),
         .watchType = WP_RW,
         .accessLen = sizeof(uint64_t),
	 .calleeCtxtFrame = callee_ctxt_frame
    };

    WP_Subscribe(&sd, false /* capture value */, true /* Function Varianc*/);
}


WP_TriggerAction_t Profiler::OnRetWatchPoint(WP_TriggerInfo_t *wpt) {
    int top = CPUEventStack.top--;
    if (!profiler_safe_enter()) return WP_DISABLE;

    if (wpt->pc == 0) wpt->pc = getContextPC(wpt->uCtxt);
    if (wpt->pc == 0) {
        profiler_safe_exit();
        return WP_DISABLE;
    }
    
     jmethodID method_id = 0;
     uint32_t method_version = 0;
     CodeCacheManager &code_cache_manager = Profiler::getProfiler().getCodeCacheManager();

     CompiledMethod *method = code_cache_manager.getMethod((uint64_t)(wpt->pc), method_id, method_version);
     if(method == nullptr) {
         profiler_safe_exit();
         return WP_DISABLE;
     }

     // fix the imprecise IP 
     void *patchedIP = wpt->pc;
     if (!wpt->pcPrecise) {
         void *startAddr = nullptr, *endAddr = nullptr; 
         method->getMethodBoundary(&startAddr, &endAddr);
         if (prevIP > startAddr && prevIP < patchedIP) 
             patchedIP = GetPatchedIP(prevIP, endAddr, wpt->pc);
         else
             patchedIP = GetPatchedIP(startAddr, endAddr, wpt->pc);
         if (!IsPCSane(wpt->pc, patchedIP)) {
             profiler_safe_exit();
             return WP_DISABLE;
         }
         wpt->pc = patchedIP;
         prevIP = patchedIP;
     }
   
    ContextFrame *calleeCtxtFrame = (ContextFrame *)wpt->sd->calleeCtxtFrame;
    Context *trapCtxt = constructContext(_asgct, wpt->uCtxt, (uint64_t)wpt->pc, method_id, method_version, calleeCtxtFrame);
    assert(trapCtxt != nullptr);
    delete calleeCtxtFrame;
    
    metrics::ContextMetrics *metrics = trapCtxt->getMetrics();
    if (metrics == nullptr) {
        metrics = new metrics::ContextMetrics();
        trapCtxt->setMetrics(metrics); 
    }
    metrics::metric_val_t metric_val;
    metric_val.i = 1;
    assert(metrics->increment(sample_cnt_metric_id, metric_val));
    uint64_t sample_cnt = metrics->getMetricVal(sample_cnt_metric_id)->i;
   
    assert(curEventId == curWatermarkId);
    for (int i = 1; i < curWatermarkId; i++) {
    	uint64_t temp;
    	assert(read(eventFd[i], &temp, sizeof(uint64_t)) > 0);
	uint64_t new_value = temp - CPUEventStack.value[top][i];

    	double mean = metrics->getMetricVal(mean_metric_id[i])->r;
    	double variance = metrics->getMetricVal(variance_metric_id[i])->r; 
    	double m2 = metrics->getMetricVal(m2_metric_id[i])->r; 
    	UpdateVarianceAndMean(sample_cnt, new_value, &mean, &variance, &m2); 
    	double cv = sqrt(variance) / mean;
    
    	metrics::metric_val_t metric_val;
    	metric_val.r = mean;
    	assert(metrics->setMetricVal(mean_metric_id[i], metric_val));
    	metric_val.r = variance;
    	assert(metrics->setMetricVal(variance_metric_id[i], metric_val));
    	metric_val.r = m2;
    	assert(metrics->setMetricVal(m2_metric_id[i], metric_val));
    	metric_val.r = cv;
    	assert(metrics->setMetricVal(cv_metric_id[i], metric_val));
	// std::cout<< new_value << " " << sample_cnt << " " << mean << " " << variance << " " << m2 << " " << cv << std::endl;
    }    

#ifdef PRINT_TRAPPED_INS
    std::ofstream *pmu_ins_output_stream = reinterpret_cast<std::ofstream *>(TD_GET(pmu_ins_output_stream));
    assert(pmu_ins_output_stream != nullptr); 
    print_single_instruction(pmu_ins_output_stream, wpt->pc);
#endif
    
    profiler_safe_exit();
    return WP_DISABLE;
}


void Profiler::GenericAnalysis(perf_sample_data_t *sampleData, void *uCtxt, jmethodID method_id, uint32_t method_version, uint32_t threshold, int metric_id2) {
    /*Context *ctxt_access = constructContext(_asgct, uCtxt, sampleData->ip, nullptr, method_id, method_version);
    if (ctxt_access != nullptr && sampleData->ip != 0) {
	metrics::ContextMetrics *metrics = ctxt_access->getMetrics();
	if (metrics == nullptr) {
	    metrics = new metrics::ContextMetrics();
	    ctxt_access->setMetrics(metrics);
	}
	metrics::metric_val_t metric_val;
	metric_val.i = 1;
	assert(metrics->increment(metric_id2, metric_val));
        totalGenericCounter += 1;
    }*/
}

Profiler::Profiler() { 
    _asgct = (ASGCT_FN)dlsym(RTLD_DEFAULT, "AsyncGetCallTrace"); 
    assert(_asgct);
}


void Profiler::init() {

std::fill_n (mean_metric_id, MAX_EVENTS, -1);	
std::fill_n (variance_metric_id, MAX_EVENTS, -1);	
std::fill_n (m2_metric_id, MAX_EVENTS, -1);	
std::fill_n (cv_metric_id, MAX_EVENTS, -1);	

#ifndef COUNT_OVERHEAD
    _method_file.open("agent-trace-method.run");
    _method_file << XML_FILE_HEADER << std::endl;
#endif

    _statistics_file.open("agent-statistics.run");
    ThreadData::thread_data_init();
    
    assert(PerfManager::processInit(JVM::getArgument()->getPerfEventList(), Profiler::OnSample));
    assert(WP_Init());
    // std::string client_name = GetClientName();
    // std::transform(client_name.begin(), client_name.end(), std::back_inserter(clientName), ::toupper);
}


void Profiler::shutdown() {
    WP_Shutdown();
    PerfManager::processShutdown();
    ThreadData::thread_data_shutdown();
    output_statistics(); 
    _statistics_file.close();
    _method_file.close();
}

void Profiler::IncrementGCCouter() {
    __sync_fetch_and_add(&GCCounter, 1);    
}

void Profiler::threadStart() { 
    std::fill_n (eventFd, MAX_EVENTS, -1);	
    // totalGenericCounter = 0;

    ThreadData::thread_data_alloc();
    ContextTree *ct_tree = new(std::nothrow) ContextTree();
    assert(ct_tree);
    TD_GET(context_state) = reinterpret_cast<void *>(ct_tree);
  
    // settup the output
    {
#ifndef COUNT_OVERHEAD
        char name_buffer[128];
        snprintf(name_buffer, 128, "agent-trace-%u.run", TD_GET(tid));
        OUTPUT *output_stream = new(std::nothrow) OUTPUT();
        assert(output_stream);
        output_stream->setFileName(name_buffer);
        output_stream->writef("%s\n", XML_FILE_HEADER);
        TD_GET(output_state) = reinterpret_cast<void *> (output_stream);
#endif
#if defined(PRINT_SAMPLED_INS) || defined(PRINT_TRAPPED_INS)
        std::ofstream *pmu_ins_output_stream = new(std::nothrow) std::ofstream();
        char file_name[128];
        snprintf(file_name, 128, "pmu-instruction-%u", TD_GET(tid));
        pmu_ins_output_stream->open(file_name, std::ios::app); 
        TD_GET(pmu_ins_output_stream) = reinterpret_cast<void *>(pmu_ins_output_stream);
#endif
    }
    // if (clientName.compare(VARIANCE_CLIENT_NAME) == 0) assert(WP_ThreadInit(Profiler::OnRetWatchPoint));
    assert(WP_ThreadInit(Profiler::OnRetWatchPoint));
    /*else if (clientName.compare(GENERIC) != 0) { 
        ERROR("Can't decode client %s", clientName.c_str());
        assert(false);
    }*/
    PopulateBlackListAddresses();
    PerfManager::setupEvents();
}


void Profiler::threadEnd() {
    PerfManager::closeEvents();
    WP_ThreadTerminate();
    // if (clientName.compare(GENERIC) != 0) {
    //	 WP_ThreadTerminate();
    // }
    ContextTree *ctxt_tree = reinterpret_cast<ContextTree *>(TD_GET(context_state));
        
#ifndef COUNT_OVERHEAD    
    OUTPUT *output_stream = reinterpret_cast<OUTPUT *>(TD_GET(output_state));
    std::unordered_set<Context *> dump_ctxt = {};
    
    if (ctxt_tree != nullptr) {
        for (auto elem : (*ctxt_tree)) {
            Context *ctxt_ptr = elem;

	    jmethodID method_id = ctxt_ptr->getFrame().method_id;
            _code_cache_manager.checkAndMoveMethodToUncompiledSet(method_id);
    
            if (ctxt_ptr->getMetrics() != nullptr && dump_ctxt.find(ctxt_ptr) == dump_ctxt.end()) { // leaf node of the redundancy pair
                dump_ctxt.insert(ctxt_ptr);
                xml::XMLObj *obj;
                obj = xml::createXMLObj(ctxt_ptr);
                if (obj != nullptr) {
                    output_stream->writef("%s", obj->getXMLStr().c_str());
                    delete obj;
                } else continue;
        
                ctxt_ptr = ctxt_ptr->getParent();
                while (ctxt_ptr != nullptr && dump_ctxt.find(ctxt_ptr) == dump_ctxt.end()) {
                    dump_ctxt.insert(ctxt_ptr);
                    obj = xml::createXMLObj(ctxt_ptr);
                    if (obj != nullptr) {
                        output_stream->writef("%s", obj->getXMLStr().c_str());
                        delete obj;
                    }
                    ctxt_ptr = ctxt_ptr->getParent();
                }
            }
        }
    }
    
    //clean up the output stream
    delete output_stream;
    TD_GET(output_state) = nullptr;
#endif
    
    //clean up the context state
    delete ctxt_tree;
    TD_GET(context_state) = nullptr;
    
#if defined(PRINT_SAMPLED_INS) || defined(PRINT_TRAPPED_INS)
    std::ofstream *pmu_ins_output_stream = reinterpret_cast<std::ofstream *>(TD_GET(pmu_ins_output_stream));
    pmu_ins_output_stream->close();
    delete pmu_ins_output_stream;
    TD_GET(pmu_ins_output_stream) = nullptr;
#endif    
    /*
    // clear up context-sample tables 
    for (int i = 0; i < MAX_EVENTS; i++) {
        std::unordered_map<Context *, SampleNum> *ctxtSampleTable = reinterpret_cast<std::unordered_map<Context *, SampleNum> *> (TD_GET(ctxt_sample_state)[i]);
        if (ctxtSampleTable != nullptr) {
            delete ctxtSampleTable;
            TD_GET(ctxt_sample_state)[i] = nullptr;
        }
    }
    */
    ThreadData::thread_data_dealloc();

    __sync_fetch_and_add(&grandTotGenericCounter, totalGenericCounter);
}


int Profiler::output_method(const char *buf) {
  _method_file << buf;
  return 0;
}


void Profiler::output_statistics() {
    
    if (clientName.compare(GENERIC) == 0) {
        _statistics_file << clientName << std::endl;
        _statistics_file << grandTotGenericCounter << std::endl;
    }
}
