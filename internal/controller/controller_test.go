package controller

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zapi-web/micro-metallb/internal/controller/mocks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
)

const (
	testNamespace = "default"
	testName      = "web"
	testKey       = testNamespace + "/" + testName
	testIP        = "10.0.0.7"
)

func newService(opts ...func(*corev1.Service)) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testName,
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: new(lbClass),
		},
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc
}

func newTestController(t *testing.T, svc *corev1.Service, ipam IPAM) (*MicroLB, *fake.Clientset, cache.Indexer) {
	t.Helper()

	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	})

	var objs []runtime.Object
	if svc != nil {
		require.NoError(t, indexer.Add(svc))
		objs = append(objs, svc)
	}

	client := fake.NewClientset(objs...)

	controller := New(client, ipam, workers)
	controller.svcLister = corelisters.NewServiceLister(indexer)

	return controller, client, indexer
}

func TestReconcileService(t *testing.T) {
	tests := []struct {
		name            string
		key             string
		svc             *corev1.Service
		setupIPAM       func(ipam *mocks.IPAM)
		setupClient     func(client *fake.Clientset)
		wantErr         string
		wantIngress     []corev1.LoadBalancerIngress
		wantNoIPAMCalls bool
	}{
		{
			name: "allocates an IP and writes it to the status",
			key:  testKey,
			svc:  newService(),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Allocate", testKey).Return(netip.MustParseAddr(testIP), nil).Once()
			},
			wantIngress: []corev1.LoadBalancerIngress{{IP: testIP}},
		},
		{
			name: "allocates an IPv6 address",
			key:  testKey,
			svc:  newService(),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Allocate", testKey).Return(netip.MustParseAddr("2001:db8::7"), nil).Once()
			},
			wantIngress: []corev1.LoadBalancerIngress{{IP: "2001:db8::7"}},
		},
		{
			name: "allocates in a non-default namespace",
			key:  "payments/api",
			svc: newService(func(s *corev1.Service) {
				s.Namespace = "payments"
				s.Name = "api"
			}),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Allocate", "payments/api").Return(netip.MustParseAddr(testIP), nil).Once()
			},
			wantIngress: []corev1.LoadBalancerIngress{{IP: testIP}},
		},
		{
			name: "releases the IP when the service no longer exists",
			key:  testKey,
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Release", testKey).Once()
			},
		},
		{
			name: "releases the IP when the service is not a LoadBalancer",
			key:  testKey,
			svc: newService(func(s *corev1.Service) {
				s.Spec.Type = corev1.ServiceTypeClusterIP
			}),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Release", testKey).Once()
			},
		},
		{
			name: "releases the IP when loadBalancerClass belongs to another controller",
			key:  testKey,
			svc: newService(func(s *corev1.Service) {
				s.Spec.LoadBalancerClass = new("metallb.io/metallb")
			}),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Release", testKey).Once()
			},
		},
		{
			name: "releases the IP when loadBalancerClass is unset",
			key:  testKey,
			svc: newService(func(s *corev1.Service) {
				s.Spec.LoadBalancerClass = nil
			}),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Release", testKey).Once()
			},
		},
		{
			name: "leaves an already assigned service untouched",
			key:  testKey,
			svc: newService(func(s *corev1.Service) {
				s.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.9"}}
			}),
			wantIngress:     []corev1.LoadBalancerIngress{{IP: "10.0.0.9"}},
			wantNoIPAMCalls: true,
		},
		{
			name: "skips a service that is being deleted",
			key:  testKey,
			svc: newService(func(s *corev1.Service) {
				now := metav1.NewTime(time.Now())
				s.DeletionTimestamp = &now
				s.Finalizers = []string{"micro-metallb.zapi-web.io/protection"}
			}),
			wantNoIPAMCalls: true,
		},
		{
			name: "returns an error when allocation fails",
			key:  testKey,
			svc:  newService(),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Allocate", testKey).Return(netip.Addr{}, errors.New("pool exhausted")).Once()
			},
			wantErr: "failed to allocate IP to LoadBalancer " + testKey,
		},
		{
			name: "returns an error when the status update fails",
			key:  testKey,
			svc:  newService(),
			setupIPAM: func(ipam *mocks.IPAM) {
				ipam.On("Allocate", testKey).Return(netip.MustParseAddr(testIP), nil).Once()
			},
			setupClient: func(client *fake.Clientset) {
				client.PrependReactor("update", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("apiserver unavailable")
				})
			},
			wantErr: "failed to update service " + testKey,
		},
		{
			name:            "ignores a queue key with an unexpected format",
			key:             "a/b/c",
			wantNoIPAMCalls: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipam := mocks.NewIPAM(t)
			if tt.setupIPAM != nil {
				tt.setupIPAM(ipam)
			}

			controller, client, _ := newTestController(t, tt.svc, ipam)
			if tt.setupClient != nil {
				tt.setupClient(client)
			}

			err := controller.reconcileService(t.Context(), tt.key)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNoIPAMCalls {
				ipam.AssertNumberOfCalls(t, "Allocate", 0)
				ipam.AssertNumberOfCalls(t, "Release", 0)
			}

			if tt.svc == nil {
				return
			}

			got, err := client.CoreV1().Services(tt.svc.Namespace).Get(t.Context(), tt.svc.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.wantIngress, got.Status.LoadBalancer.Ingress)
		})
	}
}

func TestReconcileServiceIsIdempotent(t *testing.T) {
	key := testKey
	addr := netip.MustParseAddr(testIP)

	ipam := mocks.NewIPAM(t)
	ipam.On("Allocate", key).Return(addr, nil).Once()

	controller, client, indexer := newTestController(t, newService(), ipam)

	require.NoError(t, controller.reconcileService(t.Context(), key))

	updated, err := client.CoreV1().Services(testNamespace).Get(t.Context(), testName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, indexer.Update(updated))

	require.NoError(t, controller.reconcileService(t.Context(), key))

	got, err := client.CoreV1().Services(testNamespace).Get(t.Context(), testName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, []corev1.LoadBalancerIngress{{IP: addr.String()}}, got.Status.LoadBalancer.Ingress)

	ipam.AssertNumberOfCalls(t, "Allocate", 1)
}

func TestIsOurLoadBalancer(t *testing.T) {
	tests := []struct {
		name string
		svc  *corev1.Service
		want bool
	}{
		{
			name: "LoadBalancer with matching class",
			svc:  newService(),
			want: true,
		},
		{
			name: "LoadBalancer without class",
			svc:  newService(func(s *corev1.Service) { s.Spec.LoadBalancerClass = nil }),
			want: false,
		},
		{
			name: "LoadBalancer with another class",
			svc:  newService(func(s *corev1.Service) { s.Spec.LoadBalancerClass = new("metallb.io/metallb") }),
			want: false,
		},
		{
			name: "LoadBalancer with empty class",
			svc:  newService(func(s *corev1.Service) { s.Spec.LoadBalancerClass = new("") }),
			want: false,
		},
		{
			name: "ClusterIP with matching class",
			svc:  newService(func(s *corev1.Service) { s.Spec.Type = corev1.ServiceTypeClusterIP }),
			want: false,
		},
		{
			name: "NodePort with matching class",
			svc:  newService(func(s *corev1.Service) { s.Spec.Type = corev1.ServiceTypeNodePort }),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isOurLoadBalancer(tt.svc))
		})
	}
}
