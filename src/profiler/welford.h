#ifndef __WELFORD__
#define __WELFORD__

static inline void UpdateVarianceAndMean(uint64_t sampleNum, uint64_t newValue, double *mean, double *variance, double *M2) {
    if (sampleNum < 2) {
        *mean = newValue;
        *variance = 0; 
        *M2 = 0;
    } else {
        double delta = newValue - *mean;
        *mean += delta / sampleNum;
        double delta2 = newValue - *mean;
        *M2 += delta * delta2;
        *variance = *M2 / (sampleNum - 1);
    }
}

#endif 
