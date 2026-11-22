package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const workers = 1
const lbClass = "micro-metallb"

//go:generate mockery --name IPAM
type IPAM interface {
	Allocate(key string) (netip.Addr, error)
	Reserve(key, ipStr string) error
	Release(key string)
}

type MicroLB struct {
	clientSet    kubernetes.Interface
	ipam         IPAM
	svcLister    corelisters.ServiceLister
	queue        workqueue.TypedRateLimitingInterface[string]
	wg           sync.WaitGroup
	workersCount int
}

func New(clientSet kubernetes.Interface, ipam IPAM, workersCount int) *MicroLB {
	if workersCount <= 0 {
		workersCount = workers
	}

	return &MicroLB{
		clientSet: clientSet,
		ipam:      ipam,
		queue: workqueue.NewTypedRateLimitingQueue(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](
				5*time.Second,
				5*time.Minute,
			),
		),
		workersCount: workersCount,
	}
}

func (m *MicroLB) Start(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(m.clientSet, 0)
	serviceInformer := factory.Core().V1().Services().Informer()
	m.svcLister = factory.Core().V1().Services().Lister()

	enqueue := func(obj interface{}) {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
		if err != nil {
			slog.Warn("failed to extract key", "err", err)
			return
		}

		m.queue.Add(key)
	}

	_, err := serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: enqueue,
		UpdateFunc: func(oldObj, newObj interface{}) {
			enqueue(newObj)
		},
		DeleteFunc: enqueue,
	})

	if err != nil {
		return fmt.Errorf("failed to add event handler: %w", err)
	}

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), serviceInformer.HasSynced) {
		return fmt.Errorf("failed to sync informer cache")
	}

	if err := m.ipamWarmUp(); err != nil {
		return err
	}

	for i := 0; i < m.workersCount; i++ {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.runWorker(ctx)
		}()
	}

	return nil
}

func (m *MicroLB) Stop() {
	slog.Info("shutting down queue...")
	m.queue.ShutDown()
	m.wg.Wait()
	slog.Info("all workers drained successfully")
}

func (m *MicroLB) ipamWarmUp() error {
	services, err := m.svcLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list services for IPAM warmup: %w", err)
	}

	for _, svc := range services {
		if !isOurLoadBalancer(svc) || len(svc.Status.LoadBalancer.Ingress) == 0 {
			continue
		}
		key, err := cache.MetaNamespaceKeyFunc(svc)
		if err != nil {
			continue
		}
		if err := m.ipam.Reserve(key, svc.Status.LoadBalancer.Ingress[0].IP); err != nil {
			slog.Warn("skipping invalid/stale IP during warmup", "key", key, "err", err)
		}
	}

	return nil
}

func (m *MicroLB) runWorker(ctx context.Context) {
	recServ := func(item string) error {
		defer m.queue.Done(item)
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return m.reconcileService(reqCtx, item)
	}

	for {
		item, shutdown := m.queue.Get()

		if shutdown {
			return
		}

		err := recServ(item)

		if err != nil {
			slog.Error("failed to reconcile service", "key", item, "err", err)
			m.queue.AddRateLimited(item)
		} else {
			m.queue.Forget(item)
		}
	}
}

func (m *MicroLB) reconcileService(ctx context.Context, item string) error {
	ns, name, err := cache.SplitMetaNamespaceKey(item)
	if err != nil {
		return nil
	}

	svc, err := m.svcLister.Services(ns).Get(name)
	if apierrors.IsNotFound(err) {
		m.ipam.Release(item)
		return nil
	}
	if err != nil {
		return err
	}
	if !isOurLoadBalancer(svc) {
		m.ipam.Release(item)
		return nil
	}

	if !svc.DeletionTimestamp.IsZero() {
		return nil
	}

	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		return nil
	}

	slog.Debug("received new loadBalancer", "key", item)

	receivedIP, err := m.ipam.Allocate(item)
	if err != nil {
		return fmt.Errorf("failed to allocate IP to LoadBalancer %s: %w", item, err)
	}

	svc = svc.DeepCopy()
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{
			IP: receivedIP.String(),
		},
	}

	_, err = m.clientSet.CoreV1().Services(svc.Namespace).UpdateStatus(
		ctx,
		svc,
		metav1.UpdateOptions{},
	)

	if err != nil {
		return fmt.Errorf("failed to update service %s: %w", item, err)
	}

	slog.Debug("successfully setted IP", "key", item, "ip", receivedIP.String())
	return nil
}

func isOurLoadBalancer(svc *corev1.Service) bool {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}
	return svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == lbClass
}
