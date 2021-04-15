package hook

import (
	"encoding/json"
)

//1.# console
//monitoring-platform-access
//2.# cml
//associatedCRP
//4.# warehouse
//istio-injection
//5.# compute
//istio-injection
//6.# implala
//istio-injection
//7.# monitoring
//cdp.cloudera/version

//3.# cml-user
//ds-parent-namespace

//only the # cml-user//ds-parent-namespace//
// namespace-service-ca-crt admission is to add securityContext
func createSecretModifyPatch(availableAnnotations map[string]string, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation
	// update Annotation to set admissionWebhookAnnotationStatusKey: "mutated"
	patch = append(patch, updateAnnotation(availableAnnotations, annotations)...)

	// add pod spec securityContext
	/*replaceSecurityContext := patchOperation{
		Op:   "replace",
		Path: "/spec/securityContext",
		Value: &corev1.PodSecurityContext{
			RunAsUser:  &securityContextValue,
			RunAsGroup: &securityContextValue,
			FSGroup:    &securityContextValue,
		},
	}
	glog.Infof("modify  pod spec securityContext for value: %v", replaceSecurityContext)
	patch = append(patch, replaceSecurityContext)*/
	// complete

	return json.Marshal(patch)
}




func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

