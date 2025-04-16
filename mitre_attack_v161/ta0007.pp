locals {
  mitre_attack_v161_ta0007_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0007"
  })
}

benchmark "mitre_attack_v161_ta0007" {
  title         = "TA0007 Discovery"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0007.md")
  children = [
    benchmark.mitre_attack_v161_ta0007_t1083
  ]

  tags = merge(local.mitre_attack_v161_ta0007_common_tags, {
    type = "Benchmark"
  })
} 