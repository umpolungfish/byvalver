Complete List of BYVALVER Strategies and Their Priorities

1. adc_modrm_null_bypass_strategy - Priority: 70
2. adc_immediate_null_free_strategy - Priority: 69
3. adc_sib_disp32_null_strategy - Priority: 72

4. modrm_null_bypass_strategy - Priority: 90
5. arithmetic_substitution_strategy - Priority: 85
6. flag_preserving_test_strategy - Priority: 80
7. sib_addressing_strategy - Priority: 75
8. xor_null_free_strategy - Priority: 70
9. push_optimized_strategy - Priority: 65
10. byte_granularity_strategy - Priority: 60
11. cond_jump_target_strategy - Priority: 55
12. cond_jump_target_enhanced_strategy - Priority: 50

13. peb_debug_check_strategy - Priority: 10
14. remote_debug_check_strategy - Priority: 5
15. output_debug_check_strategy - Priority: 5
16. timing_check_strategy - Priority: 8
17. int3_detection_strategy - Priority: 7
18. parent_check_strategy - Priority: 5

19. hash_verification_adjustment_strategy - Priority: 82
20. null_safe_hash_storage_strategy - Priority: 80

21. arithmetic_const_generation_strategy - Priority: 70
22. arithmetic_build_value_strategy - Priority: 75

23. mov_arith_decomp_strategy - Priority: 70

24. arithmetic_flag_preservation_strategy - Priority: 87
25. flag_preserving_decomposition_strategy - Priority: 85

26. arithmetic_original_strategy - Priority: 10
27. arithmetic_neg_strategy - Priority: 9
28. arithmetic_not_strategy - Priority: 9
29. arithmetic_xor_strategy - Priority: 7
30. arithmetic_addsub_strategy - Priority: 7

31. arithmetic_substitution_strategy - Priority: 74

32. arpl_modrm_null_strategy - Priority: 75

33. bit_manipulation_constant_strategy - Priority: 84
34. rotation_xor_constant_strategy - Priority: 82

35. bound_modrm_null_strategy - Priority: 70

36. bt_imm_null_strategy - Priority: 80

37. byte_construct_strategy - Priority: 5

38. cmp_mem_disp_null_strategy - Priority: 55

39. cmp_reg_imm_null_strategy - Priority: 85
40. cmp_byte_mem_imm_null_strategy - Priority: 88
41. cmp_mem_reg_null_strategy - Priority: 86

42. movx_disp_nulls_strategy - Priority: 80
43. fallback_immediate_replacement_strategy - Priority: 50
44. general_mem_nulls_strategy - Priority: 75

45. conditional_flag_manipulation_strategy - Priority: 90
46. conditional_jump_flag_transform_strategy - Priority: 85

47. conditional_jump_null_offset_strategy - Priority: 150

48. conservative_mov_original_strategy - Priority: 16

49. conservative_mov_strategy - Priority: 15
50. conservative_arithmetic_strategy - Priority: 14

51. context_aware_strategy - Priority: 100

52. mov_reg_reg_strategy - Priority: 17
53. incdec_reg_strategy - Priority: 15
54. xor_reg_reg_strategy - Priority: 16
55. push_pop_reg_strategy - Priority: 17

56. custom_hash_pattern_strategy - Priority: 85
57. xor_encoded_hash_strategy - Priority: 80

58. arithmetic_neg_enhanced_strategy - Priority: 75
59. arithmetic_xor_enhanced_strategy - Priority: 72
60. arithmetic_addsub_enhanced_strategy - Priority: 70

61. immediate_splitting_enhanced_strategy - Priority: 80
62. small_immediate_enhanced_strategy - Priority: 78
63. large_immediate_enhanced_strategy - Priority: 82

64. mov_mem_imm_enhanced_strategy - Priority: 75
65. generic_mem_null_disp_enhanced_strategy - Priority: 65

66. register_chaining_immediate_enhanced_strategy - Priority: 70
67. cross_register_operation_enhanced_strategy - Priority: 68

68. flag_based_conditional_jumps_strategy - Priority: 95
69. flag_mirror_conditional_jumps_strategy - Priority: 90

70. fpu_modrm_null_bypass_strategy - Priority: 60
71. fpu_sib_null_strategy - Priority: 65

72. push_imm32_strategy - Priority: 9 (in general_strategies.c)
73. stack_string_strategy - Priority: 10 (in general_strategies.c)

74. getpc_mov_strategy - Priority: 25

75. immediate_split_strategy - Priority: 77

76. arithmetic_neg_proper_strategy - Priority: 80
77. arithmetic_xor_proper_strategy - Priority: 78
78. arithmetic_addsub_proper_strategy - Priority: 76

79. mov_neg_proper_strategy - Priority: 75
80. mov_not_proper_strategy - Priority: 74
81. mov_addsub_proper_strategy - Priority: 60

82. imul_modrm_null_bypass_strategy - Priority: 72
83. imul_immediate_null_free_strategy - Priority: 71

84. indirect_call_mem_strategy - Priority: 100
85. indirect_jmp_mem_strategy - Priority: 100

86. call_imm_strategy - Priority: 8
87. call_mem_disp32_strategy - Priority: 8
88. jmp_mem_disp32_strategy - Priority: 8
89. generic_mem_null_disp_strategy - Priority: 3

90. large_immediate_strategy - Priority: 85

91. lea_complex_displacement_strategy - Priority: 80
92. lea_displacement_adjusted_strategy - Priority: 75

93. lea_disp_nulls_strategy - Priority: 8
94. lea_null_modrm_strategy - Priority: 65

95. socketcall_argument_array_strategy - Priority: 75
96. socketcall_constant_strategy - Priority: 72

97. safe_string_push_strategy - Priority: 70
98. null_free_path_construction_strategy - Priority: 68

99. loop_strategy - Priority: 80
100. jecxz_strategy - Priority: 80
101. loope_strategy - Priority: 75
102. loopne_strategy - Priority: 75

103. lea_disp_null_strategy - Priority: 85
104. mov_mem_disp_null_strategy - Priority: 83
105. general_mem_disp_null_strategy - Priority: 82

106. mov_mem_imm_strategy - Priority: 8
107. mov_mem_dst_strategy - Priority: 8
108. cmp_mem_reg_strategy - Priority: 8
109. arith_mem_imm_strategy - Priority: 7
110. lea_disp32_strategy - Priority: 10

111. mov_original_strategy - Priority: 10
112. mov_neg_strategy - Priority: 13
113. mov_not_strategy - Priority: 12
114. mov_xor_strategy - Priority: 6
115. mov_shift_strategy - Priority: 7
116. mov_addsub_strategy - Priority: 11

117. movzx_null_elimination_strategy - Priority: 75

118. multibyte_nop_strategy - Priority: 90

119. transform_mov_reg_mem_self - Priority: 5
120. transform_add_mem_reg8 - Priority: 5
121. delayed_string_termination_strategy - Priority: 90

122. test_to_and_strategy - Priority: 80
123. mov_push_pop_strategy - Priority: 75
124. arithmetic_negation_strategy - Priority: 85
125. junk_code_strategy - Priority: 90
126. opaque_predicate_strategy - Priority: 95

127. peb_api_hashing_strategy - Priority: 95
128. hash_based_api_resolution_strategy - Priority: 90

129. alt_peb_traversal_strategy - Priority: 9
130. standard_peb_traversal_strategy - Priority: 8

131. push_immediate_nulls_strategy - Priority: 75
132. push_immediate_nulls_alt_strategy - Priority: 70

133. push_sib_addressing_strategy - Priority: 80
134. push_sib_memory_strategy - Priority: 75
135. push_advanced_sib_strategy - Priority: 70

136. register_chaining_immediate_strategy - Priority: 65
137. cross_register_operation_strategy - Priority: 60

138. register_swap_loading_strategy - Priority: 85
139. stack_swap_loading_strategy - Priority: 80
140. byte_construct_loading_strategy - Priority: 75

141. relative_jump_strategy - Priority: 85

142. lea_disp_enhanced_strategy - Priority: 2
143. mov_mem_disp_enhanced_strategy - Priority: 2
144. mov_imm_enhanced_strategy - Priority: 2
145. arithmetic_imm_enhanced_strategy - Priority: 2

146. rep_stosb_count_setup_strategy - Priority: 92

147. ret_immediate_strategy - Priority: 78

148. retf_immediate_null_strategy - Priority: 85

149. rip_relative_strategy - Priority: 80

150. robust_jump_strategy - Priority: 85

151. ror13_hash_strategy - Priority: 90

152. ror_rol_immediate_strategy - Priority: 70

153. safe_sib_null_strategy - Priority: 5

154. salc_rep_stosb_null_fill_strategy - Priority: 50
155. clc_salc_zero_strategy - Priority: 65

156. salc_zero_al_strategy - Priority: 91

157. salc_zero_register_strategy - Priority: 95
158. salc_zero_al_direct_strategy - Priority: 98

159. sbb_modrm_null_bypass_strategy - Priority: 70
160. sbb_immediate_null_free_strategy - Priority: 69

161. xor_zero_reg_strategy - Priority: 18
162. push_immediate_optimized_strategy - Priority: 15
163. mov_reg_preserve_sequence_strategy - Priority: 17
164. incdec_reg_simple_strategy - Priority: 16

165. setcc_modrm_null_bypass_strategy - Priority: 75
166. setcc_conditional_mov_strategy - Priority: 70

167. shift_based_strategy - Priority: 5

168. sib_displacement_nulls_strategy - Priority: 90
169. sib_adjusted_displacement_strategy - Priority: 85

170. sib_null_strategy - Priority: 65

171. sldt_replacement - Priority: 95

172. sldt_register_dest_strategy - Priority: 75
173. sldt_modrm_null_bypass_strategy - Priority: 70

174. small_immediate_strategy - Priority: 75

175. socket_xor_ip_strategy - Priority: 80
176. socket_bytewise_ip_strategy - Priority: 78
177. socket_port_encoding_strategy - Priority: 77

178. stack_constant_generation_strategy - Priority: 86
179. stack_arithmetic_constant_strategy - Priority: 84

180. stack_string_const_construction_strategy - Priority: 85
181. byte_chunk_push_strategy - Priority: 80

182. stack_string_construction_strategy - Priority: 88
183. stack_multi_string_construction_strategy - Priority: 85

184. enhanced_stack_string_strategy - Priority: 85

185. string_instruction_byte_construction_strategy - Priority: 82
186. stosd_construction_strategy - Priority: 80

187. string_instruction_null_construct_strategy - Priority: 45
188. byte_by_byte_construction_strategy - Priority: 40

189. syscall_number_byte_based_strategy - Priority: 78
190. syscall_number_push_pop_strategy - Priority: 77

191. syscall_number_mov_strategy - Priority: 95

192. test_mem_null_strategy - Priority: 82

193. unicode_stosw_strategy - Priority: 93
194. unicode_ascii_conversion_strategy - Priority: 89

195. xchg_immediate_loading_strategy - Priority: 60
196. xchg_stack_loading_strategy - Priority: 55

197. push_imm_preservation_strategy - Priority: 86

198. xchg_mem_strategy - Priority: 60

199. xor_runtime_encoding_strategy - Priority: 75
200. xor_mem_encoding_strategy - Priority: 70

201. xor_reg_zeroing_strategy - Priority: 100
202. push_pop_zero_reg_strategy - Priority: 75

203. lea_zero_disp_strategy - Priority: 84
204. test_imm_nulls_strategy - Priority: 80
205. mov_zero_disp_strategy - Priority: 82

Total Strategies: 205