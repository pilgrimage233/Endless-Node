package cc.endmc.endlessnode;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@MapperScan("cc.endmc.endlessnode.mapper")
@EnableScheduling
public class EndlessNodeApplication {

    public static void main(String[] args) {
        SpringApplication.run(EndlessNodeApplication.class, args);
    }

}
