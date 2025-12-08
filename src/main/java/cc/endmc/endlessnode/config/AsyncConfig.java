package cc.endmc.endlessnode.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
@EnableAsync
public class AsyncConfig {

    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // 核心线程数：保持2个线程常驻
        executor.setCorePoolSize(2);
        // 最大线程数：支持最多10个并发安装任务
        executor.setMaxPoolSize(10);
        // 队列容量：额外排队50个任务
        executor.setQueueCapacity(50);
        // 线程名称前缀
        executor.setThreadNamePrefix("JavaInstall-");
        // 拒绝策略：队列满时由调用线程执行
        executor.setRejectedExecutionHandler(new java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy());
        // 线程空闲时间：60秒后回收
        executor.setKeepAliveSeconds(60);
        // 允许核心线程超时
        executor.setAllowCoreThreadTimeOut(true);
        executor.initialize();
        return executor;
    }
} 