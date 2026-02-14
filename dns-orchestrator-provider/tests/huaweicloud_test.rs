//! Huaweicloud DNS Provider integration test
//!
//! Operation mode:
//! ```bash
//! HUAWEICLOUD_ACCESS_KEY_ID=xxx HUAWEICLOUD_SECRET_ACCESS_KEY=xxx TEST_DOMAIN=example.com \
//!     cargo test -p dns-orchestrator-provider --test huaweicloud_test -- --ignored --nocapture --test-threads=1
//! ```

mod common;

use common::{TestContext, TestRecordType, get_test_record_data};
use dns_orchestrator_provider::{
    CreateDnsRecordRequest, PaginationParams, RecordQueryParams, UpdateDnsRecordRequest,
};

// ============ Basic Test ============

#[tokio::test]
#[ignore = "integration test: requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY and TEST_DOMAIN"]
async fn test_huaweicloud_validate_credentials() {
    skip_if_no_credentials!(
        "HUAWEICLOUD_ACCESS_KEY_ID",
        "HUAWEICLOUD_SECRET_ACCESS_KEY",
        "TEST_DOMAIN"
    );

    let ctx = require_some!(TestContext::huaweicloud(), "创建测试上下文失败");
    let valid = require_ok!(
        ctx.provider.validate_credentials().await,
        "validate_credentials 调用失败"
    );
    assert!(valid, "凭证应该有效");

    println!("✓ validate_credentials 测试通过");
}

#[tokio::test]
#[ignore = "integration test: requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY and TEST_DOMAIN"]
async fn test_huaweicloud_list_domains() {
    skip_if_no_credentials!(
        "HUAWEICLOUD_ACCESS_KEY_ID",
        "HUAWEICLOUD_SECRET_ACCESS_KEY",
        "TEST_DOMAIN"
    );

    let ctx = require_some!(TestContext::huaweicloud(), "创建测试上下文失败");
    let params = PaginationParams::default();

    let response = require_ok!(
        ctx.provider.list_domains(&params).await,
        "list_domains 调用失败"
    );
    assert!(!response.items.is_empty(), "域名列表不应为空");

    println!(
        "✓ list_domains 测试通过，共 {} 个域名",
        response.total_count
    );
}

#[tokio::test]
#[ignore = "integration test: requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY and TEST_DOMAIN"]
async fn test_huaweicloud_get_domain() {
    skip_if_no_credentials!(
        "HUAWEICLOUD_ACCESS_KEY_ID",
        "HUAWEICLOUD_SECRET_ACCESS_KEY",
        "TEST_DOMAIN"
    );

    let mut ctx = require_some!(TestContext::huaweicloud(), "创建测试上下文失败");
    let domain_id = require_some!(ctx.find_domain_id().await, "找不到测试域名");

    let domain = require_ok!(
        ctx.provider.get_domain(&domain_id).await,
        "get_domain 调用失败"
    );
    assert_eq!(domain.name, ctx.domain, "域名名称不匹配");

    println!("✓ get_domain 测试通过: {}", domain.name);
}

#[tokio::test]
#[ignore = "integration test: requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY and TEST_DOMAIN"]
async fn test_huaweicloud_list_records() {
    skip_if_no_credentials!(
        "HUAWEICLOUD_ACCESS_KEY_ID",
        "HUAWEICLOUD_SECRET_ACCESS_KEY",
        "TEST_DOMAIN"
    );

    let mut ctx = require_some!(TestContext::huaweicloud(), "创建测试上下文失败");
    let domain_id = require_some!(ctx.find_domain_id().await, "找不到测试域名");

    let params = RecordQueryParams::default();
    let response = require_ok!(
        ctx.provider.list_records(&domain_id, &params).await,
        "list_records 调用失败"
    );
    println!(
        "✓ list_records 测试通过，共 {} 条记录",
        response.total_count
    );
}

// ============ Cleanup Test ============

/// Clean up any remaining test records (run manually)
#[tokio::test]
#[ignore = "integration test: requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY and TEST_DOMAIN"]
async fn test_huaweicloud_cleanup_test_records() {
    skip_if_no_credentials!(
        "HUAWEICLOUD_ACCESS_KEY_ID",
        "HUAWEICLOUD_SECRET_ACCESS_KEY",
        "TEST_DOMAIN"
    );

    let mut ctx = require_some!(TestContext::huaweicloud(), "创建测试上下文失败");
    let domain_id = require_some!(ctx.find_domain_id().await, "找不到测试域名");

    ctx.cleanup_all_test_records(&domain_id).await;
    println!("✓ 清理完成");
}

// ============ CRUD test macro ============

macro_rules! crud_test {
    ($test_name:ident, $record_type:expr, $type_name:expr, $name_gen:expr) => {
        #[tokio::test]
        #[ignore = "integration test: requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY and TEST_DOMAIN"]
        async fn $test_name() {
            skip_if_no_credentials!(
                "HUAWEICLOUD_ACCESS_KEY_ID",
                "HUAWEICLOUD_SECRET_ACCESS_KEY",
                "TEST_DOMAIN"
            );

            let mut ctx = require_some!(TestContext::huaweicloud(), "创建测试上下文失败");
            let domain_id = require_some!(ctx.find_domain_id().await, "找不到测试域名");

            let record_name = $name_gen();
            let (create_data, update_data) = get_test_record_data($record_type);

            println!("测试 {} 记录: {}", $type_name, record_name);

            // 0. Clean up possible records with the same name (to prevent residues)
            let cleanup_params = RecordQueryParams {
                page: 1,
                page_size: 100,
                keyword: Some(record_name.clone()),
                record_type: None,
            };
            if let Ok(response) = ctx.provider.list_records(&domain_id, &cleanup_params).await {
                for record in response.items {
                    if record.name.contains(&record_name) {
                        let _ = ctx.provider.delete_record(&record.id, &domain_id).await;
                        println!("  ⚠ 清理残留记录: {}", record.id);
                    }
                }
            }

            // 1. Create a record
            let create_req = CreateDnsRecordRequest {
                domain_id: domain_id.clone(),
                name: record_name.clone(),
                ttl: 600,
                data: create_data,
                proxied: None,
            };

            let created_record = require_ok!(
                ctx.provider.create_record(&create_req).await,
                "create_record 失败"
            );
            let record_id = created_record.id.clone();
            println!("  ✓ 创建成功: id={}", record_id);

            // 2. Verify that the record exists
            let search_params = RecordQueryParams {
                page: 1,
                page_size: 100,
                keyword: Some(record_name.clone()),
                record_type: None,
            };

            let list_response = require_ok!(
                ctx.provider.list_records(&domain_id, &search_params).await,
                "list_records 失败"
            );
            let found = list_response.items.iter().any(|r| r.id == record_id);
            assert!(found, "创建的记录应该能被搜索到");
            println!("  ✓ 验证存在");

            // 3. Update records
            let update_req = UpdateDnsRecordRequest {
                domain_id: domain_id.clone(),
                name: record_name.clone(),
                ttl: 300,
                data: update_data,
                proxied: None,
            };

            let updated_record = require_ok!(
                ctx.provider.update_record(&record_id, &update_req).await,
                "update_record 失败"
            );
            assert_eq!(updated_record.ttl, 300, "TTL 应该被更新为 300");
            println!("  ✓ 更新成功");

            // 4. Delete records
            require_ok!(
                ctx.provider.delete_record(&record_id, &domain_id).await,
                "delete_record 失败"
            );
            println!("  ✓ 删除成功");

            // 5. Verify deleted
            let verify_result = ctx.provider.list_records(&domain_id, &search_params).await;
            if let Ok(response) = verify_result {
                let still_exists = response.items.iter().any(|r| r.id == record_id);
                assert!(!still_exists, "记录应该已被删除");
            }
            println!("  ✓ 验证删除");

            println!("✓ {} 记录 CRUD 测试通过", $type_name);
        }
    };
}

// ============ Various types of CRUD tests ============

crud_test!(
    test_huaweicloud_crud_a_record,
    TestRecordType::A,
    "A",
    common::generate_test_record_name
);
crud_test!(
    test_huaweicloud_crud_aaaa_record,
    TestRecordType::Aaaa,
    "AAAA",
    common::generate_test_record_name
);
crud_test!(
    test_huaweicloud_crud_cname_record,
    TestRecordType::Cname,
    "CNAME",
    common::generate_test_record_name
);
crud_test!(
    test_huaweicloud_crud_mx_record,
    TestRecordType::Mx,
    "MX",
    common::generate_test_record_name
);
crud_test!(
    test_huaweicloud_crud_txt_record,
    TestRecordType::Txt,
    "TXT",
    common::generate_test_record_name
);
crud_test!(
    test_huaweicloud_crud_srv_record,
    TestRecordType::Srv,
    "SRV",
    common::generate_srv_test_record_name
);
crud_test!(
    test_huaweicloud_crud_caa_record,
    TestRecordType::Caa,
    "CAA",
    common::generate_test_record_name
);
